"""Public-safe backend for the Streamlit product boundary.

Only fixed public assets are readable here.  Every canonical object is projected
immediately into immutable display models; raw rows and runtime artifacts never
escape this module.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Final

from riec_guard.benchmarks.catalog import (
    json_asset_bytes,
    parse_json_object,
    validate_benchmark_identity,
    validate_catalog_identity,
)
from riec_guard.benchmarks.models import (
    DemoBenchmarkSummary,
    DemoScenarioResult,
    RecordedScenarioSummary,
    SCENARIO_ORDER,
    ScenarioCatalog,
    ScenarioDefinition,
)
from riec_guard.benchmarks.runner import run_public_demo_scenario
from riec_guard.contract.models import DatasetProfile, ProtocolId, ProtocolResultEntry
from riec_guard.contract.profiler import profile_dataset
from riec_guard.domain.source import SourceRepository
from riec_guard.errors import ErrorClass, ErrorEnvelope, ErrorStage
from riec_guard.gpt.client import OpenAIResponsesClient, StructuredGptClient
from riec_guard.gpt.memo import build_recorded_evidence_context
from riec_guard.gpt.models import EvidenceContext, GptWorkflowResult
from riec_guard.gpt.workflow import (
    build_fixture_gpt_client,
    run_gpt_interpretation_workflow,
)
from riec_guard.settings import RuntimeSettings
from riec_guard.ui.copy import (
    ACTION_LABELS,
    PROTOCOL_NAMES,
    PROTOCOL_ROLES,
    RECORDED_SOURCE_EXPLANATION,
    RECORDED_SOURCE_LABEL,
    RECOMPUTED_SOURCE_EXPLANATION,
    RECOMPUTED_SOURCE_LABEL,
)
from riec_guard.ui.models import (
    UiClaimReview,
    UiDecisionSnapshot,
    UiDownloadPacket,
    UiEvidenceNode,
    UiGateStatus,
    UiGptCall,
    UiGptFinding,
    UiGptResult,
    UiGptRoleSuggestion,
    UiProtocolRow,
    UiScenarioBundle,
    UiScenarioDefinition,
)

_REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[3]
_CATALOG_PATH: Final = ("demo_assets", "scenario_catalog.v1.json")
_SUMMARY_PATH: Final = ("demo_assets", "benchmark_summary.v1.json")
_CATALOG_BYTES_SHA256: Final = "f1112a8148293c610875610f16f1d520c55eb9187f24a7cf44f1d316486bc018"
_CATALOG_CONTENT_SHA256: Final = "decb3631b261978dfeb9deb95615988f34a7d493aaf58af91cff0a73018ad90a"
_SUMMARY_BYTES_SHA256: Final = "c5c054f726760da52010a03da3b9ebff25846213d5f8e069058c45e189df4669"
_SUMMARY_CONTENT_SHA256: Final = "008c3d576e563cfce2bfe6c9137bbc283130834a00f154364da92194d5bf9a76"
_SCENARIO_RECORDS_SHA256: Final = "fe31074a363f68fdf4f8194fa754449963bd20efdfb424a8217a1da3e5b70b52"
_CATALOG_SIZE: Final = 9_668
_SUMMARY_SIZE: Final = 12_481
_CSV_SIZE: Final = 68_651
_CSV_HEADER: Final = (
    "quantity",
    "product",
    "batch_id",
    "timestamp",
    "stream",
    "shift",
    "row_sequence",
)
_SCENARIO_CSV: Final[dict[str, tuple[tuple[str, ...], str]]] = {
    "stable_symmetric": (
        ("data", "public_synthetic", "stable_symmetric.csv"),
        "61406ba1733671cbe91350925e4e23a011bbd6b49c90d9d59ab16a74c23c8b5f",
    ),
    "heavy_tail_particulate": (
        ("data", "public_synthetic", "heavy_tail_particulate.csv"),
        "9e92d093d625de0df94c201daed84752a73791ce07eda92a16e39b9a7e22562f",
    ),
    "batch_drift_change_point": (
        ("data", "public_synthetic", "batch_drift_change_point.csv"),
        "fe3a280f6bd084e59b533083d97826d719eec58b8c01840102a6367a455abf24",
    ),
}
_SCENARIO_DISPLAY_NAMES: Final = {
    "stable_symmetric": "Stable symmetric process",
    "heavy_tail_particulate": "Heavy-tail particulate variation",
    "batch_drift_change_point": "Batch drift and change point",
}
_PROTOCOL_ORDER: Final = (
    ProtocolId.D0_MEAN_DIAGNOSTIC,
    ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE,
    ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL,
    ProtocolId.H3_STUDENT_T_RESIDUAL_TAIL,
    ProtocolId.U1_GROUP_BOOTSTRAP_BOUND,
    ProtocolId.G1_ORDERED_STABILITY_SCREEN,
    ProtocolId.G2_EVIDENCE_SUFFICIENCY_GATE,
)


def load_verified_scenario_definitions() -> tuple[UiScenarioDefinition, ...] | ErrorEnvelope:
    """Return the fixed display order after verifying every committed asset."""

    try:
        catalog, summary = _load_assets()
        definitions: list[UiScenarioDefinition] = []
        for scenario_id in _SCENARIO_CSV:
            definition, record, csv_bytes = _verified_inputs(
                scenario_id,
                catalog=catalog,
                summary=summary,
            )
            _validate_scenario_binding(definition, record, csv_bytes, catalog, summary)
            definitions.append(_project_definition(definition))
        return tuple(definitions)
    except (OSError, TypeError, ValueError, csv.Error):
        return _ui_error(
            "UI_RECORDED_ASSET_INVALID",
            "The recorded public demonstration assets failed integrity validation.",
            user_action="Use the accepted committed public assets and retry.",
        )


def load_verified_recorded_scenario(scenario_id: str) -> UiScenarioBundle | ErrorEnvelope:
    """Load one exact allowlisted recorded scenario and fail closed on any drift."""

    if type(scenario_id) is not str or scenario_id not in _SCENARIO_CSV:
        return _ui_error(
            "UI_SCENARIO_NOT_REGISTERED",
            "The requested public demonstration scenario is not registered.",
            recoverable=True,
            user_action="Choose one of the three registered public scenarios.",
        )
    try:
        catalog, summary = _load_assets()
        definition, record, csv_bytes = _verified_inputs(
            scenario_id,
            catalog=catalog,
            summary=summary,
        )
        _validate_scenario_binding(definition, record, csv_bytes, catalog, summary)
        return _project_bundle(
            definition,
            record,
            catalog,
            summary,
            result_source=RECORDED_SOURCE_LABEL,
            source_explanation=RECORDED_SOURCE_EXPLANATION,
        )
    except (OSError, TypeError, ValueError, csv.Error):
        return _ui_error(
            "UI_RECORDED_ASSET_INVALID",
            "The recorded public demonstration assets failed integrity validation.",
            user_action="Use the accepted committed public assets and retry.",
        )


def recompute_public_scenario(scenario_id: str) -> UiScenarioBundle | ErrorEnvelope:
    """Explicitly run one fixed scenario through the accepted production defaults."""

    recorded = load_verified_recorded_scenario(scenario_id)
    if isinstance(recorded, ErrorEnvelope):
        return recorded
    try:
        with tempfile.TemporaryDirectory(prefix="riec-guard-ui-recompute-") as temporary:
            repository = SourceRepository(
                RuntimeSettings(ephemeral_root=Path(temporary) / "ephemeral-runs")
            )
            result = run_public_demo_scenario(repository, scenario_id=scenario_id)
        if isinstance(result, ErrorEnvelope):
            return result
        if not isinstance(result, DemoScenarioResult):
            raise ValueError("unsupported recompute result")
        catalog, summary = _load_assets()
        expected = next(item for item in summary.scenarios if item.scenario_id.value == scenario_id)
        if result.summary != expected:
            raise ValueError("recomputed result drifted from the accepted record")
        protocol_entries = tuple(result.protocols.results)
        if tuple(entry.protocol_id for entry in protocol_entries) != _PROTOCOL_ORDER:
            raise ValueError("recomputed protocol order is invalid")
        definition = next(
            item for item in catalog.scenarios if item.scenario_id.value == scenario_id
        )
        d0_entry = next(
            entry
            for entry in protocol_entries
            if entry.protocol_id is ProtocolId.D0_MEAN_DIAGNOSTIC
        )
        return _project_bundle(
            definition,
            result.summary,
            catalog,
            summary,
            result_source=RECOMPUTED_SOURCE_LABEL,
            source_explanation=RECOMPUTED_SOURCE_EXPLANATION,
            d0_entry=d0_entry,
        )
    except (OSError, TypeError, ValueError):
        return _ui_error(
            "UI_RECOMPUTE_FAILED",
            "The deterministic audit could not be recomputed safely.",
            recoverable=True,
            user_action="Keep using the verified recorded audit or retry once.",
        )


def run_fixture_gpt_workflow(scenario_id: str) -> UiGptResult | ErrorEnvelope:
    """Run all three accepted GPT stages through the deterministic fixture transport."""

    context = _prepare_gpt_context(scenario_id)
    if isinstance(context, ErrorEnvelope):
        return context
    profile, evidence_context = context
    result = run_gpt_interpretation_workflow(
        dataset_profile=profile,
        evidence_context=evidence_context,
        client=build_fixture_gpt_client(),
    )
    if isinstance(result, ErrorEnvelope):
        return result
    return _project_gpt_result(result, scenario_id=scenario_id, mode_label="Fixture / non-live")


def run_live_gpt_workflow(
    scenario_id: str,
    *,
    deployment_credential: str,
    client: StructuredGptClient | None = None,
) -> UiGptResult | ErrorEnvelope:
    """Run one explicit live workflow without persisting or globally exporting the key."""

    if type(deployment_credential) is not str or not deployment_credential.strip():
        return _ui_error(
            "UI_LIVE_GPT_NOT_CONFIGURED",
            "Live GPT-5.6 is not configured for this deployment.",
            stage=ErrorStage.GPT,
            recoverable=True,
            user_action="Configure the server-side deployment secret or use fixture mode.",
        )
    context = _prepare_gpt_context(scenario_id)
    if isinstance(context, ErrorEnvelope):
        return context
    profile, evidence_context = context
    active_client = client
    if active_client is None:

        def client_factory(*, timeout: object, max_retries: int) -> object:
            import httpx
            from openai import OpenAI

            if not isinstance(timeout, httpx.Timeout):
                raise TypeError("the accepted client requires a bounded HTTP timeout")
            return OpenAI(api_key=deployment_credential, timeout=timeout, max_retries=max_retries)

        active_client = OpenAIResponsesClient(client_factory=client_factory)
    result = run_gpt_interpretation_workflow(
        dataset_profile=profile,
        evidence_context=evidence_context,
        client=active_client,
    )
    if isinstance(result, ErrorEnvelope):
        return result
    return _project_gpt_result(result, scenario_id=scenario_id, mode_label="Live GPT-5.6")


def build_download_packet(
    bundle: UiScenarioBundle,
    *,
    gpt_result: UiGptResult | None = None,
) -> UiDownloadPacket | ErrorEnvelope:
    """Build one in-memory allowlisted JSON packet with a fixed safe filename."""

    if not isinstance(bundle, UiScenarioBundle) or (
        gpt_result is not None
        and (
            not isinstance(gpt_result, UiGptResult)
            or gpt_result.scenario_id != bundle.definition.scenario_id
        )
    ):
        return _ui_error(
            "UI_DOWNLOAD_INPUT_INVALID",
            "The decision download could not be constructed from the selected scenario.",
            recoverable=True,
            user_action="Reload the selected public scenario and retry.",
        )
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "product": {"name": "RIEC Guard", "version": "public-demo.v1"},
        "scenario": {
            "scenario_id": bundle.definition.scenario_id,
            "scenario_version": bundle.definition.scenario_version,
            "display_name": bundle.definition.display_name,
            "classification": bundle.definition.classification,
            "mechanism_description": bundle.definition.mechanism_description,
        },
        "source": {
            "mode": (
                "recorded_production_default"
                if bundle.result_source == RECORDED_SOURCE_LABEL
                else "recomputed_production_default"
            ),
            "display_label": bundle.result_source,
            "dataset_sha256": bundle.dataset_sha256,
            "catalog_sha256": bundle.catalog_sha256,
            "summary_sha256": bundle.summary_sha256,
            "contract_id": bundle.contract_id,
        },
        "design": {
            "rows": bundle.row_count,
            "deployment_groups": bundle.deployment_group_count,
            "products": bundle.product_count,
            "rows_per_product": bundle.rows_per_product,
        },
        "policy": {
            "profile_id": bundle.policy_profile_id,
            "nominal_quantity": bundle.nominal_quantity,
            "lower_limit": bundle.lower_limit,
            "alpha": bundle.alpha,
            "measurement_resolution": bundle.measurement_resolution,
            "minimum_actionable_shift": bundle.minimum_actionable_shift,
            "maximum_screening_shift": bundle.maximum_screening_shift,
            "protocol_spread_tolerance": bundle.protocol_spread_tolerance,
            "bootstrap_replicates": bundle.bootstrap_replicates,
            "bootstrap_seed": bundle.bootstrap_seed,
            "unit": bundle.decision.unit,
        },
        "riec": {
            "winner": bundle.riec_winner,
            "runner_up": bundle.riec_runner_up,
            "near_tie": bundle.riec_near_tie,
            "equivalence_set": bundle.equivalence_set,
        },
        "protocols": tuple(_protocol_download(row) for row in bundle.protocols),
        "gates": tuple(_gate_download(gate) for gate in bundle.gates),
        "conflict": {
            "material": bundle.decision.protocol_conflict,
            "spread": bundle.decision.protocol_spread,
            "spread_tolerance": bundle.protocol_spread_tolerance,
            "summary": bundle.decision.conflict_summary,
        },
        "action": {
            "state": bundle.decision.action_state,
            "label": bundle.decision.action_label,
            "decisive_reason": bundle.decision.decisive_reason,
            "pilot_min": bundle.decision.pilot_min,
            "pilot_max": bundle.decision.pilot_max,
            "unit": bundle.decision.unit,
            "interpretation": "retrospective screening reference",
        },
        "limitations": bundle.limitations,
        "evidence": tuple(_evidence_download(node) for node in bundle.evidence_nodes),
        "gpt": None if gpt_result is None else _gpt_download(gpt_result),
    }
    encoded = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")
    return UiDownloadPacket(
        filename=f"riec_guard_{bundle.definition.scenario_id}_decision.json",
        media_type="application/json",
        content=encoded,
        content_sha256=hashlib.sha256(encoded).hexdigest(),
    )


def _load_assets() -> tuple[ScenarioCatalog, DemoBenchmarkSummary]:
    catalog_bytes = _read_fixed_bytes(
        _CATALOG_PATH,
        expected_size=_CATALOG_SIZE,
        expected_sha256=_CATALOG_BYTES_SHA256,
    )
    summary_bytes = _read_fixed_bytes(
        _SUMMARY_PATH,
        expected_size=_SUMMARY_SIZE,
        expected_sha256=_SUMMARY_BYTES_SHA256,
    )
    catalog = ScenarioCatalog.model_validate(parse_json_object(catalog_bytes))
    summary = DemoBenchmarkSummary.model_validate(parse_json_object(summary_bytes))
    validate_catalog_identity(catalog)
    validate_benchmark_identity(summary, catalog=catalog)
    if (
        catalog.content_sha256 != _CATALOG_CONTENT_SHA256
        or summary.content_sha256 != _SUMMARY_CONTENT_SHA256
        or summary.scenario_records_sha256 != _SCENARIO_RECORDS_SHA256
        or catalog_bytes != json_asset_bytes(catalog)
        or summary_bytes != json_asset_bytes(summary)
        or tuple(item.value for item in catalog.fixed_order) != tuple(_SCENARIO_CSV)
        or catalog.fixed_order != SCENARIO_ORDER
    ):
        raise ValueError("accepted public asset identities changed")
    return catalog, summary


def _verified_inputs(
    scenario_id: str,
    *,
    catalog: ScenarioCatalog,
    summary: DemoBenchmarkSummary,
) -> tuple[ScenarioDefinition, RecordedScenarioSummary, bytes]:
    asset = _SCENARIO_CSV.get(scenario_id)
    if asset is None:
        raise ValueError("scenario is not allowlisted")
    relative_parts, expected_sha256 = asset
    csv_bytes = _read_fixed_bytes(
        relative_parts,
        expected_size=_CSV_SIZE,
        expected_sha256=expected_sha256,
    )
    definition = next(item for item in catalog.scenarios if item.scenario_id.value == scenario_id)
    record = next(item for item in summary.scenarios if item.scenario_id.value == scenario_id)
    return definition, record, csv_bytes


def _validate_scenario_binding(
    definition: ScenarioDefinition,
    record: RecordedScenarioSummary,
    csv_bytes: bytes,
    catalog: ScenarioCatalog,
    summary: DemoBenchmarkSummary,
) -> None:
    row_count, group_count, product_counts = _csv_counts(csv_bytes)
    expected_hash = _SCENARIO_CSV[definition.scenario_id.value][1]
    if (
        definition.policy != catalog.shared_policy
        or definition.policy != summary.shared_policy
        or record.policy_profile_id != definition.policy.profile_id
        or record.dataset_sha256 != expected_hash
        or row_count != definition.design.row_count
        or row_count != record.row_count
        or group_count != definition.design.deployment_group_count
        or group_count != record.deployment_group_count
        or len(product_counts) != definition.design.product_count
        or len(product_counts) != record.product_count
        or tuple(sorted(product_counts.values()))
        != (definition.design.rows_per_product,) * definition.design.product_count
        or record.rows_per_product != definition.design.rows_per_product
        or record.expected_tail_count_per_product
        != definition.design.expected_tail_count_per_product
        or record.action_state is not definition.expectation.action_state
        or record.g1_state is not definition.expectation.g1_state
        or record.g2.action_supported is not definition.expectation.g2_action_supported
        or record.protocol_conflict is not definition.expectation.protocol_conflict
        or record.g2.alpha != definition.policy.alpha
        or record.g2.expected_tail_count != definition.design.expected_tail_count_per_product
        or record.g2.minimum_product_rows != definition.design.rows_per_product
        or record.g2.minimum_product_groups != definition.design.deployment_group_count
        or record.u1.requested_replicates != definition.policy.bootstrap_replicates
        or record.u1.seed != definition.policy.bootstrap_seed
        or record.u1.successful_replicates + record.u1.failed_replicates
        != record.u1.requested_replicates
    ):
        raise ValueError("scenario policy, design, or recorded outcome is inconsistent")
    pilot_present = record.pilot_min is not None and record.pilot_max is not None
    if definition.expectation.positive_pilot_interval:
        if (
            not pilot_present
            or record.pilot_min is None
            or record.pilot_max is None
            or not (0.0 < record.pilot_min <= record.pilot_max)
        ):
            raise ValueError("positive pilot expectation is inconsistent")
    elif record.pilot_min is not None or record.pilot_max is not None:
        raise ValueError("a no-pilot scenario contains an interval")
    expected_components = ("RIEC", "PROTOCOL", "ACTION")
    if tuple(node.component for node in record.evidence_chain) != expected_components:
        raise ValueError("recorded evidence components are invalid")
    riec, protocol, action = record.evidence_chain
    for node in record.evidence_chain:
        expected_id = f"EV-{node.component}-{node.content_sha256[:12].upper()}"
        if node.evidence_id != expected_id:
            raise ValueError("recorded evidence identity is invalid")
    if (
        riec.evidence_id != record.riec_evidence_id
        or protocol.evidence_id != record.protocol_evidence_id
        or action.evidence_id != record.action_evidence_id
        or riec.parent_evidence_ids
        or protocol.parent_evidence_ids != (riec.evidence_id,)
        or set(action.parent_evidence_ids) != {riec.evidence_id, protocol.evidence_id}
    ):
        raise ValueError("recorded evidence ancestry is invalid")


def _read_fixed_bytes(
    relative_parts: tuple[str, ...],
    *,
    expected_size: int,
    expected_sha256: str,
) -> bytes:
    path = _REPOSITORY_ROOT.joinpath(*relative_parts)
    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise OSError("fixed public asset is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_size != expected_size
        ):
            raise OSError("fixed public asset changed while opening")
        chunks: list[bytes] = []
        remaining = expected_size + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        len(data) != expected_size
        or after.st_dev != opened.st_dev
        or after.st_ino != opened.st_ino
        or after.st_size != opened.st_size
        or hashlib.sha256(data).hexdigest() != expected_sha256
    ):
        raise OSError("fixed public asset failed byte validation")
    return data


def _csv_counts(csv_bytes: bytes) -> tuple[int, int, dict[str, int]]:
    reader = csv.DictReader(
        io.StringIO(csv_bytes.decode("utf-8", errors="strict"), newline=""),
        strict=True,
    )
    if tuple(reader.fieldnames or ()) != _CSV_HEADER:
        raise ValueError("public CSV header is invalid")
    row_count = 0
    groups: set[str] = set()
    product_counts: dict[str, int] = {}
    for row in reader:
        if None in row or any(value is None or value == "" for value in row.values()):
            raise ValueError("public CSV row is structurally invalid")
        row_count += 1
        group = row["batch_id"]
        product = row["product"]
        groups.add(group)
        product_counts[product] = product_counts.get(product, 0) + 1
    return row_count, len(groups), product_counts


def _project_definition(definition: ScenarioDefinition) -> UiScenarioDefinition:
    return UiScenarioDefinition(
        scenario_id=definition.scenario_id.value,
        scenario_version=definition.scenario_version,
        display_name=_SCENARIO_DISPLAY_NAMES[definition.scenario_id.value],
        mechanism_description=definition.mechanism_description,
        domain_hint=definition.domain_hint,
        classification=definition.classification,
        limitation=definition.limitation,
    )


def _project_bundle(
    definition: ScenarioDefinition,
    record: RecordedScenarioSummary,
    catalog: ScenarioCatalog,
    summary: DemoBenchmarkSummary,
    *,
    result_source: str,
    source_explanation: str,
    d0_entry: ProtocolResultEntry | None = None,
) -> UiScenarioBundle:
    action_state = record.action_state.value
    action_label = ACTION_LABELS.get(action_state)
    if action_label is None:
        raise ValueError("action state has no public display label")
    policy = summary.shared_policy
    limitations = _ordered_unique(
        (
            definition.limitation,
            *catalog.limitations,
            *summary.limitations,
            "Any pilot range is a retrospective screening reference requiring a controlled pilot and engineering review.",
        )
    )
    return UiScenarioBundle(
        definition=_project_definition(definition),
        result_source=result_source,
        source_explanation=source_explanation,
        dataset_sha256=record.dataset_sha256,
        catalog_sha256=catalog.content_sha256,
        summary_sha256=summary.content_sha256,
        contract_id=record.contract_id,
        policy_profile_id=record.policy_profile_id,
        row_count=record.row_count,
        deployment_group_count=record.deployment_group_count,
        product_count=record.product_count,
        rows_per_product=record.rows_per_product,
        nominal_quantity=float(policy.nominal_quantity),
        lower_limit=float(policy.lower_limit),
        alpha=float(policy.alpha),
        measurement_resolution=float(policy.measurement_resolution),
        minimum_actionable_shift=float(policy.minimum_actionable_shift),
        maximum_screening_shift=float(policy.maximum_screening_shift),
        protocol_spread_tolerance=float(policy.protocol_spread_tolerance),
        bootstrap_replicates=policy.bootstrap_replicates,
        bootstrap_seed=policy.bootstrap_seed,
        riec_winner=record.riec_winner,
        riec_runner_up=record.riec_runner_up,
        riec_near_tie=record.riec_near_tie,
        equivalence_set=tuple(record.equivalence_set),
        decision=UiDecisionSnapshot(
            action_state=action_state,
            action_label=action_label,
            decisive_reason=record.decisive_reason,
            pilot_min=None if record.pilot_min is None else float(record.pilot_min),
            pilot_max=None if record.pilot_max is None else float(record.pilot_max),
            unit=record.unit,
            protocol_conflict=record.protocol_conflict,
            conflict_summary=_conflict_summary(record),
            protocol_spread=(
                None if record.protocol_spread is None else float(record.protocol_spread)
            ),
        ),
        protocols=_protocol_rows(record, d0_entry=d0_entry),
        gates=_gate_rows(record),
        bootstrap_requested=record.u1.requested_replicates,
        bootstrap_successful=record.u1.successful_replicates,
        bootstrap_failed=record.u1.failed_replicates,
        evidence_nodes=tuple(
            UiEvidenceNode(
                component=node.component,
                evidence_id=node.evidence_id,
                content_sha256=node.content_sha256,
                parent_evidence_ids=tuple(node.parent_evidence_ids),
            )
            for node in record.evidence_chain
        ),
        limitations=limitations,
    )


def _protocol_rows(
    record: RecordedScenarioSummary,
    *,
    d0_entry: ProtocolResultEntry | None,
) -> tuple[UiProtocolRow, ...]:
    rows: list[UiProtocolRow] = []
    if d0_entry is not None:
        rows.append(
            UiProtocolRow(
                protocol_id="D0",
                name=PROTOCOL_NAMES["D0"],
                status=d0_entry.status.value,
                value=(None if d0_entry.point_estimate is None else float(d0_entry.point_estimate)),
                lower_bound=(
                    None
                    if d0_entry.uncertainty is None or d0_entry.uncertainty.lower is None
                    else float(d0_entry.uncertainty.lower)
                ),
                unit=d0_entry.unit,
                role_limitation=PROTOCOL_ROLES["D0"],
            )
        )
    displays = (("H1", record.h1), ("H2", record.h2), ("H3", record.h3))
    for short, display in displays:
        rows.append(
            UiProtocolRow(
                protocol_id=short,
                name=PROTOCOL_NAMES[short],
                status=display.status.value,
                value=None if display.value is None else float(display.value),
                lower_bound=(None if display.lower_bound is None else float(display.lower_bound)),
                unit=display.unit,
                role_limitation=PROTOCOL_ROLES[short],
            )
        )
    rows.append(
        UiProtocolRow(
            protocol_id="U1",
            name=PROTOCOL_NAMES["U1"],
            status=record.u1.status.value,
            value=None if record.u1.lower_bound is None else float(record.u1.lower_bound),
            lower_bound=(None if record.u1.lower_bound is None else float(record.u1.lower_bound)),
            unit=record.unit,
            role_limitation=PROTOCOL_ROLES["U1"],
        )
    )
    return tuple(rows)


def _gate_rows(record: RecordedScenarioSummary) -> tuple[UiGateStatus, ...]:
    g1_detail = {
        "pass": "Ordered stability screen passed without a material warning.",
        "material_warning": (
            "Ordered stability contains a material warning and blocks a pilot interval."
        ),
        "ineligible": "Ordered stability evidence is unavailable for action support.",
    }[record.g1_state.value]
    g2_detail = (
        f"{record.g2.minimum_product_rows} rows and "
        f"{record.g2.minimum_product_groups} deployment groups per product; "
        f"expected strict-tail support {record.g2.expected_tail_count:.2f} at "
        f"alpha {record.g2.alpha:.2f}."
    )
    return (
        UiGateStatus(
            gate_id="G1",
            status=record.g1_state.value,
            supports_action=record.g1_state.value == "pass",
            detail=g1_detail,
        ),
        UiGateStatus(
            gate_id="G2",
            status="supported" if record.g2.action_supported else "not_supported",
            supports_action=record.g2.action_supported,
            detail=g2_detail,
        ),
    )


def _conflict_summary(record: RecordedScenarioSummary) -> str:
    if not record.protocol_conflict:
        return "No material protocol conflict is recorded for this scenario."
    if record.action_state.value == "diagnose_process_first":
        return "Material conflict is recorded; the ordered-stability warning is decisive."
    return "Material protocol conflict is recorded; the action remains conservative."


def _prepare_gpt_context(
    scenario_id: str,
) -> tuple[DatasetProfile, EvidenceContext] | ErrorEnvelope:
    if type(scenario_id) is not str or scenario_id not in _SCENARIO_CSV:
        return _ui_error(
            "UI_SCENARIO_NOT_REGISTERED",
            "The requested public demonstration scenario is not registered.",
            recoverable=True,
            user_action="Choose one of the three registered public scenarios.",
        )
    try:
        catalog, summary = _load_assets()
        definition, record, csv_bytes = _verified_inputs(
            scenario_id,
            catalog=catalog,
            summary=summary,
        )
        _validate_scenario_binding(definition, record, csv_bytes, catalog, summary)
        profile = _profile_committed_csv(definition, csv_bytes)
        context = build_recorded_evidence_context(
            dataset_profile=profile,
            catalog=catalog,
            benchmark_summary=summary,
            scenario_id=scenario_id,
        )
        return profile, context
    except (OSError, TypeError, ValueError, csv.Error):
        return _ui_error(
            "UI_GPT_CONTEXT_INVALID",
            "The public evidence context could not be prepared safely.",
            stage=ErrorStage.GPT,
            recoverable=True,
            user_action="Keep using the deterministic audit or retry narrative assistance later.",
        )


def _profile_committed_csv(
    definition: ScenarioDefinition,
    csv_bytes: bytes,
) -> DatasetProfile:
    with tempfile.TemporaryDirectory(prefix="riec-guard-ui-profile-") as temporary:
        repository = SourceRepository(
            RuntimeSettings(ephemeral_root=Path(temporary) / "ephemeral-runs")
        )
        roots = repository.create_run()
        profile: DatasetProfile | ErrorEnvelope
        try:
            source = repository.register_built_in(
                roots.run_id,
                built_in_key=definition.scenario_id.value,
                display_name=definition.display_name,
                payload=csv_bytes,
            )
            profile = profile_dataset(
                repository,
                run_id=roots.run_id,
                source_id=source.source_id,
            )
        finally:
            repository.delete_run(roots.run_id)
    if not isinstance(profile, DatasetProfile):
        raise ValueError("public profile construction failed")
    return profile


def _project_gpt_result(
    result: GptWorkflowResult,
    *,
    scenario_id: str,
    mode_label: str,
) -> UiGptResult:
    contract = result.contract_suggestion
    memo = result.decision_memo
    audit = result.claim_audit
    return UiGptResult(
        scenario_id=scenario_id,
        context_source="recorded_production_default",
        mode_label=mode_label,
        status=result.status.value,
        user_message=result.user_message,
        fixture_non_live=result.fixture_non_live,
        deterministic_analysis_available=result.deterministic_analysis_available,
        requested_model=result.requested_model,
        prompt_versions=tuple(result.prompt_versions),
        workflow_sha256=result.normalized_output_sha256,
        contract_suggestions=(
            ()
            if contract is None
            else tuple(
                UiGptRoleSuggestion(
                    role=item.role.value,
                    column=item.column,
                    confidence=float(item.confidence),
                    reason=item.reason,
                )
                for item in contract.role_suggestions
            )
        ),
        requires_human_confirmation=(
            None if contract is None else contract.requires_human_confirmation
        ),
        analysis_permitted=None if contract is None else contract.analysis_permitted,
        memo_title=None if memo is None else memo.title,
        decision_snapshot=None if memo is None else memo.decision_snapshot,
        evidence_summary=None if memo is None else memo.what_the_evidence_shows,
        protocol_explanation=None if memo is None else memo.why_protocol_choice_matters,
        recommended_next_step=None if memo is None else memo.recommended_next_step,
        memo_limitations=() if memo is None else tuple(memo.limitations),
        findings=(
            ()
            if memo is None
            else tuple(
                UiGptFinding(
                    finding_id=item.finding_id,
                    statement=item.statement,
                    evidence_ids=tuple(item.evidence_ids),
                    fact_keys=tuple(item.fact_keys),
                    importance=item.importance.value,
                )
                for item in memo.findings
            )
        ),
        claim_audit_status=None if audit is None else audit.status.value,
        deterministic_validation_status=(
            None if audit is None else audit.deterministic_validation_status
        ),
        claim_reviews=(
            ()
            if audit is None
            else tuple(
                UiClaimReview(
                    claim_id=item.claim_id,
                    verdict=item.verdict.value,
                    reason=item.reason,
                    evidence_ids=tuple(item.evidence_ids),
                    fact_keys=tuple(item.fact_keys),
                    suggested_revision=item.suggested_revision,
                )
                for item in audit.reviews
            )
        ),
        referenced_evidence_ids=tuple(result.referenced_evidence_ids),
        calls=tuple(
            UiGptCall(
                task=item.task.value,
                status=item.status.value,
                execution_mode=item.execution_mode.value,
                requested_model=item.requested_model,
                returned_model=item.returned_model,
                prompt_version=item.prompt_version,
                response_id=item.response_id,
                input_sha256=item.sanitized_input_sha256,
                output_sha256=item.normalized_output_sha256,
                attempt_count=item.attempt_count,
                input_tokens=item.usage.input_tokens,
                output_tokens=item.usage.output_tokens,
                total_tokens=item.usage.total_tokens,
                error_code=item.error_code,
            )
            for item in result.audit_trail
        ),
    )


def _protocol_download(row: UiProtocolRow) -> dict[str, object]:
    return {
        "protocol_id": row.protocol_id,
        "name": row.name,
        "status": row.status,
        "value": row.value,
        "lower_bound": row.lower_bound,
        "unit": row.unit,
        "role_limitation": row.role_limitation,
    }


def _gate_download(gate: UiGateStatus) -> dict[str, object]:
    return {
        "gate_id": gate.gate_id,
        "status": gate.status,
        "supports_action": gate.supports_action,
        "detail": gate.detail,
    }


def _evidence_download(node: UiEvidenceNode) -> dict[str, object]:
    return {
        "component": node.component,
        "evidence_id": node.evidence_id,
        "content_sha256": node.content_sha256,
        "parent_evidence_ids": node.parent_evidence_ids,
    }


def _gpt_download(result: UiGptResult) -> dict[str, object]:
    return {
        "context_source": result.context_source,
        "mode": result.mode_label,
        "status": result.status,
        "fixture_non_live": result.fixture_non_live,
        "deterministic_analysis_available": result.deterministic_analysis_available,
        "requested_model": result.requested_model,
        "prompt_versions": result.prompt_versions,
        "workflow_sha256": result.workflow_sha256,
        "contract_suggestions": tuple(
            {
                "role": item.role,
                "column": item.column,
                "confidence": item.confidence,
                "reason": item.reason,
            }
            for item in result.contract_suggestions
        ),
        "requires_human_confirmation": result.requires_human_confirmation,
        "analysis_permitted": result.analysis_permitted,
        "memo": {
            "title": result.memo_title,
            "decision_snapshot": result.decision_snapshot,
            "what_the_evidence_shows": result.evidence_summary,
            "why_protocol_choice_matters": result.protocol_explanation,
            "recommended_next_step": result.recommended_next_step,
            "limitations": result.memo_limitations,
            "findings": tuple(
                {
                    "finding_id": item.finding_id,
                    "statement": item.statement,
                    "evidence_ids": item.evidence_ids,
                    "fact_keys": item.fact_keys,
                    "importance": item.importance,
                }
                for item in result.findings
            ),
        },
        "claim_audit": {
            "status": result.claim_audit_status,
            "deterministic_validation_status": result.deterministic_validation_status,
            "reviews": tuple(
                {
                    "claim_id": item.claim_id,
                    "verdict": item.verdict,
                    "reason": item.reason,
                    "evidence_ids": item.evidence_ids,
                    "fact_keys": item.fact_keys,
                    "suggested_revision": item.suggested_revision,
                }
                for item in result.claim_reviews
            ),
            "referenced_evidence_ids": result.referenced_evidence_ids,
        },
        "calls": tuple(
            {
                "task": item.task,
                "status": item.status,
                "execution_mode": item.execution_mode,
                "requested_model": item.requested_model,
                "returned_model": item.returned_model,
                "prompt_version": item.prompt_version,
                "response_id": item.response_id,
                "sanitized_input_sha256": item.input_sha256,
                "normalized_output_sha256": item.output_sha256,
                "attempt_count": item.attempt_count,
                "input_tokens": item.input_tokens,
                "output_tokens": item.output_tokens,
                "total_tokens": item.total_tokens,
                "error_code": item.error_code,
            }
            for item in result.calls
        ),
    }


def _ordered_unique(values: tuple[str, ...]) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        if value not in result:
            result.append(value)
    return tuple(result)


def _ui_error(
    code: str,
    message: str,
    *,
    stage: ErrorStage = ErrorStage.EXPORT,
    error_class: ErrorClass = ErrorClass.SECURITY_BLOCK,
    recoverable: bool = False,
    user_action: str,
) -> ErrorEnvelope:
    digest = hashlib.sha256(
        f"{stage.value}\0{error_class.value}\0{code}".encode("utf-8")
    ).hexdigest()[:12]
    return ErrorEnvelope.model_validate(
        {
            "schema_version": "1.0.0",
            "error_id": f"ERR-{digest.upper()}",
            "stage": stage,
            "error_class": error_class,
            "code": code,
            "message": message,
            "recoverable": recoverable,
            "user_action": user_action,
            "safe_details": {},
            "cause_chain": (),
        }
    )


__all__ = [
    "build_download_packet",
    "load_verified_recorded_scenario",
    "load_verified_scenario_definitions",
    "recompute_public_scenario",
    "run_fixture_gpt_workflow",
    "run_live_gpt_workflow",
]
