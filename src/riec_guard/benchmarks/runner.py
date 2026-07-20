"""Safe end-to-end runner for the fixed public synthetic scenarios."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from riec_guard.app_service import AuditService, FillProtocolActionResult
from riec_guard.benchmarks.catalog import (
    canonical_sha256,
    seal_benchmark_summary,
    seal_record,
)
from riec_guard.benchmarks.models import (
    DemoBenchmarkSummary,
    DemoG1State,
    DemoScenarioResult,
    GeneratedScenario,
    ProtocolDisplay,
    RecordedScenarioSummary,
    SCENARIO_ORDER,
    ScenarioDefinition,
)
from riec_guard.benchmarks.scenarios import (
    generate_scenario,
    get_scenario_definition,
    shared_policy,
)
from riec_guard.contract.canonicalize import (
    CONFIRMATION_FIELD_ORDER,
    canonicalize_audit_contract,
)
from riec_guard.contract.models import (
    ActionDecision,
    AuditContract,
    ConfirmedBy,
    DatasetProfile,
    ProtocolId,
    ProtocolResult,
    ProtocolResultEntry,
    RiecSelection,
)
from riec_guard.contract.profiler import profile_dataset
from riec_guard.contract.schema_loader import load_schema_registry
from riec_guard.contract.validator import (
    analysis_is_permitted,
    confirm_audit_contract,
    validate_audit_contract,
)
from riec_guard.domain.source import SourceRepository
from riec_guard.errors import ErrorClass, ErrorEnvelope, ErrorStage
from riec_guard.evidence.ids import verify_evidence_item
from riec_guard.evidence.ledger import EvidenceLedgerBuilder, verify_ledger
from riec_guard.evidence.models import EvidenceComponent, EvidenceLedger
from riec_guard.evidence.provenance import ProvenanceGraph
from riec_guard.riec.registry import RunRegistrySnapshot, load_run_registry_snapshot

_NORMALIZED_RUN_ID = "RUN-000000000000"
_CONTRACT_CREATED_AT = "2026-07-18T08:00:00Z"
_CONTRACT_CONFIRMED_AT = "2026-07-18T08:01:00Z"
_POLICY_SOURCE_TITLE = "RIEC Guard public synthetic demo policy v1"
_POLICY_SOURCE_TEXT = (
    "RIEC Guard public synthetic demo policy v1: nominal_quantity=250.00 mL; "
    "lower_limit=249.50 mL; alpha=0.01; measurement_resolution=0.01 mL; "
    "minimum_actionable_shift=0.05 mL; maximum_screening_shift=0.50 mL; "
    "protocol_spread_tolerance=0.50 mL."
)
_POLICY_SOURCE_SHA256 = hashlib.sha256(_POLICY_SOURCE_TEXT.encode("utf-8")).hexdigest()


def run_public_demo_scenario(
    repository: SourceRepository,
    *,
    scenario_id: str,
    registry_snapshot: RunRegistrySnapshot | None = None,
) -> DemoScenarioResult | ErrorEnvelope:
    """Run one registered public scenario through the accepted production service.

    The returned canonical artifacts retain their ephemeral canonical run ID.  The
    recorded display summary is run-neutral and contains no source ID, path, or row.
    """

    if not isinstance(repository, SourceRepository):
        return _error(
            "DEMO_REPOSITORY_INVALID",
            stage=ErrorStage.UPLOAD,
            error_class=ErrorClass.VALIDATION,
            message="The public demo runner requires a safe source repository.",
            recoverable=False,
            user_action="Create a public SourceRepository and retry the registered scenario.",
        )
    try:
        definition = get_scenario_definition(scenario_id)
    except (TypeError, ValueError):
        return _error(
            "DEMO_SCENARIO_NOT_REGISTERED",
            stage=ErrorStage.CONTRACT,
            error_class=ErrorClass.VALIDATION,
            message="The requested public demonstration scenario is not registered.",
            recoverable=True,
            user_action="Choose one of the three registered public scenario IDs.",
        )

    if registry_snapshot is not None and not isinstance(registry_snapshot, RunRegistrySnapshot):
        return _error(
            "DEMO_REGISTRY_INVALID",
            stage=ErrorStage.CONTRACT,
            error_class=ErrorClass.SECURITY_BLOCK,
            message="The supplied registry snapshot is not a trusted typed snapshot.",
            recoverable=False,
            user_action="Use the immutable run registry snapshot.",
        )
    try:
        snapshot = registry_snapshot or load_run_registry_snapshot()
        generated = generate_scenario(definition.scenario_id)
    except Exception:
        return _error(
            "DEMO_SETUP_FAILED",
            stage=ErrorStage.CONTRACT,
            error_class=ErrorClass.INTERNAL,
            message="The registered public scenario could not be prepared safely.",
            recoverable=False,
            user_action="Preserve the safe error artifact for review.",
        )

    source_run_id: str | None = None
    outcome: DemoScenarioResult | ErrorEnvelope
    try:
        roots = repository.create_run()
        source_run_id = roots.run_id
        outcome = _run_created_scenario(
            repository,
            source_run_id=source_run_id,
            generated=generated,
            registry_snapshot=snapshot,
        )
    except Exception:
        outcome = _error(
            "DEMO_EXECUTION_FAILED",
            stage=ErrorStage.PROTOCOL,
            error_class=ErrorClass.INTERNAL,
            message="The public demonstration scenario could not be completed safely.",
            recoverable=False,
            user_action="Preserve the safe error artifact for review.",
        )

    cleanup_failed = False
    if source_run_id is not None:
        try:
            cleanup_failed = not repository.delete_run(source_run_id)
        except Exception:
            cleanup_failed = True
    if cleanup_failed:
        return _error(
            "DEMO_RUN_CLEANUP_FAILED",
            stage=ErrorStage.EXPORT,
            error_class=ErrorClass.SECURITY_BLOCK,
            message="The ephemeral public demonstration run could not be removed safely.",
            recoverable=False,
            user_action="Stop processing and clean the isolated runtime root.",
        )
    return outcome


def build_recorded_summary(
    results: Sequence[DemoScenarioResult],
    *,
    catalog_sha256: str,
) -> DemoBenchmarkSummary:
    """Seal three real, run-neutral scenario records in fixed catalog order."""

    values = tuple(results)
    if (
        len(values) != len(SCENARIO_ORDER)
        or any(not isinstance(result, DemoScenarioResult) for result in values)
        or tuple(result.definition.scenario_id for result in values) != SCENARIO_ORDER
    ):
        raise ValueError("demo results must contain the three fixed scenarios in order")
    return seal_benchmark_summary(
        tuple(result.summary for result in values),
        catalog_sha256=catalog_sha256,
    )


def _run_created_scenario(
    repository: SourceRepository,
    *,
    source_run_id: str,
    generated: GeneratedScenario,
    registry_snapshot: RunRegistrySnapshot,
) -> DemoScenarioResult | ErrorEnvelope:
    definition = generated.definition
    source = repository.register_built_in(
        source_run_id,
        built_in_key=definition.scenario_id.value,
        display_name=definition.display_name,
        payload=generated.csv_bytes,
    )
    if (
        source.normalized_sha256 != generated.dataset_sha256
        or source.raw_sha256 != generated.dataset_sha256
    ):
        return _error(
            "DEMO_DATASET_NORMALIZATION_DRIFT",
            stage=ErrorStage.UPLOAD,
            error_class=ErrorClass.SECURITY_BLOCK,
            message="The public scenario bytes changed at the normalized source boundary.",
            recoverable=False,
            user_action="Stop the run and inspect the deterministic CSV generator.",
        )

    profile = profile_dataset(
        repository,
        run_id=source_run_id,
        source_id=source.source_id,
    )
    if isinstance(profile, ErrorEnvelope):
        return profile
    if (
        not isinstance(profile, DatasetProfile)
        or profile.dataset_sha256 != generated.dataset_sha256
    ):
        return _error(
            "DEMO_PROFILE_IDENTITY_MISMATCH",
            stage=ErrorStage.PROFILE,
            error_class=ErrorClass.SECURITY_BLOCK,
            message="The public scenario profile does not match the generated dataset.",
            recoverable=False,
            user_action="Stop the run and regenerate the public scenario.",
        )

    contract, contract_sha256 = _confirmed_contract(
        definition,
        profile,
        registry_snapshot,
    )
    artifact_run_id = f"RUN-{source_run_id[4:16].upper()}"
    builder = EvidenceLedgerBuilder(artifact_run_id)
    service_result = AuditService().run_audit(
        repository,
        run_id=source_run_id,
        source_id=source.source_id,
        contract=contract,
        dataset_profile=profile,
        registry_snapshot=registry_snapshot,
        evidence_builder=builder,
    )
    if isinstance(service_result, ErrorEnvelope):
        return service_result
    if not isinstance(service_result, FillProtocolActionResult):
        raise ValueError("public demo service returned an unsupported result")
    if (
        service_result.riec.dataset_sha256 != generated.dataset_sha256
        or service_result.riec.contract_id != contract.contract_id
        or service_result.riec.contract_sha256 != contract_sha256
        or service_result.riec.artifact_run_id != artifact_run_id
        or service_result.riec.selection.run_id != artifact_run_id
        or service_result.protocols.run_id != artifact_run_id
        or service_result.action.run_id != artifact_run_id
        or service_result.protocols.contract_id != contract.contract_id
        or service_result.action.contract_id != contract.contract_id
    ):
        raise ValueError("public demo service identity changed during analysis")

    _validate_canonical_results(service_result)
    _validate_unfinalized_chain(service_result, builder)
    ledger = builder.finalize()
    verification = verify_ledger(
        ledger,
        expected_run_id=artifact_run_id,
        bound_items=builder.bound_items,
    )
    _validate_finalized_chain(service_result, ledger, verification.graph)
    _validate_schema("evidence_ledger", ledger.to_canonical_dict())
    EvidenceLedger.model_validate(ledger.to_canonical_dict())

    summary = _recorded_scenario_summary(
        definition,
        service_result,
        ledger,
        dataset_sha256=generated.dataset_sha256,
        contract_sha256=contract_sha256,
    )
    return DemoScenarioResult(
        definition=definition,
        selection=service_result.riec.selection,
        protocols=service_result.protocols,
        action=service_result.action,
        evidence_ledger=ledger,
        summary=summary,
    )


def _confirmed_contract(
    definition: ScenarioDefinition,
    profile: DatasetProfile,
    registry_snapshot: RunRegistrySnapshot,
) -> tuple[AuditContract, str]:
    policy = shared_policy()
    if definition.policy != policy:
        raise ValueError("scenario policy does not match the fixed public demo policy")
    evidence_profile = registry_snapshot.evidence_profile.payload.to_contract_evidence_profile()
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "contract_id": "AC-000000000000",
        "created_at": _CONTRACT_CREATED_AT,
        "compiler": {
            "mode": "versioned_builtin",
            "model": None,
            "structured_output_schema_version": "1.0.0",
            "fallback_used": False,
            "request_id": None,
        },
        "source": {
            "mode": "builtin_synthetic",
            "dataset_id": profile.dataset_id,
            "dataset_sha256": profile.dataset_sha256,
            "filename_display": f"{definition.scenario_id.value}.csv",
            "row_count": profile.row_count,
            "column_count": len(profile.column_profiles),
            "encoding": "internal",
            "synthetic_mechanism": definition.scenario_id.value,
        },
        "column_mapping": {
            "quantity": {"column": "quantity", "confidence": 1.0, "confirmed": True},
            "product": {"column": "product", "confidence": 1.0, "confirmed": True},
            "deployment_group": {
                "column": "batch_id",
                "confidence": 1.0,
                "confirmed": True,
            },
            "time": {"column": "timestamp", "confidence": 1.0, "confirmed": True},
            "stream": {"column": "stream", "confidence": 1.0, "confirmed": True},
            "shift": {"column": "shift", "confidence": 1.0, "confirmed": True},
        },
        "measurement": {
            "quantity_semantics": "volume",
            "unit": policy.unit,
            "measurement_resolution": policy.measurement_resolution,
            "conversion": {
                "required": False,
                "method": "none",
                "fixed_density": None,
                "formula_note": None,
            },
        },
        "grouping": {
            "deployment_unit_name": "synthetic deployment group",
            "deployment_group_columns": ("batch_id",),
            "nested_context_columns": ("stream", "shift"),
            "no_random_row_fallback": True,
        },
        "ordering": {
            "status": "confirmed",
            "time_column": "timestamp",
            "timezone": "UTC",
            "within_stream_order_confirmed": True,
            "tie_break_columns": ("row_sequence",),
        },
        "policy": {
            "nominal_quantity": policy.nominal_quantity,
            "lower_limit": policy.lower_limit,
            "underfill_event": "adjusted_quantity_strictly_less_than_lower_limit",
            "alpha": policy.alpha,
            "minimum_actionable_shift": policy.minimum_actionable_shift,
            "maximum_screening_shift": policy.maximum_screening_shift,
            "protocol_spread_tolerance": policy.protocol_spread_tolerance,
            "policy_source": {
                "kind": "builtin_profile",
                "title": _POLICY_SOURCE_TITLE,
                "text_sha256": _POLICY_SOURCE_SHA256,
                "user_confirmed": True,
            },
            "notes": "Illustrative public synthetic demo values; not regulatory constants.",
        },
        "evidence_profile": evidence_profile.to_canonical_dict(),
        "riec": {
            "candidate_registry_id": registry_snapshot.candidate_registry.logical_id,
            "baseline_candidate_id": "M0_intercept",
            "risk_aggregation": "row_weighted_grouped_mse",
            "group_balanced_diagnostic": True,
            "c": 1.0,
            "near_tie_abs_tol": 0.000001,
            "near_tie_rel_tol": 0.00000001,
            "splitter": "leave_one_deployment_group_out",
            "max_exact_logo_groups": (
                registry_snapshot.evidence_profile.payload.max_exact_logo_groups
            ),
        },
        "privacy": {
            "classification": "public_synthetic",
            "raw_rows_to_gpt": False,
            "direct_identifiers_to_gpt": False,
            "storage_mode": "ephemeral_public_session",
            "redacted_summary_allowed": True,
        },
        "unresolved_fields": (),
        "assumptions": (
            {
                "assumption_id": "ASM-001",
                "text": (
                    "The public scenario policy is illustrative and confirmed for this "
                    "versioned synthetic demonstration."
                ),
                "source": "builtin_profile",
                "user_confirmed": True,
            },
        ),
        "confirmation": {
            "status": "draft",
            "confirmed_fields": (),
            "confirmed_at": None,
            "confirmed_by": "none",
        },
    }
    draft = canonicalize_audit_contract(payload)
    draft_validation = validate_audit_contract(draft, profile)
    if not draft_validation.valid or analysis_is_permitted(draft_validation):
        raise ValueError("public demo draft contract has an invalid pre-confirmation state")
    transition = confirm_audit_contract(
        draft,
        profile,
        confirmed_fields=CONFIRMATION_FIELD_ORDER,
        confirmed_by=ConfirmedBy.VERSIONED_BUILTIN,
        confirmed_at=_CONTRACT_CONFIRMED_AT,
    )
    if (
        not transition.transitioned
        or transition.idempotent
        or not transition.validation.valid
        or not analysis_is_permitted(transition.validation)
        or not transition.validation.g1_eligible
        or transition.validation.canonical_contract_sha256 is None
    ):
        raise ValueError("public demo contract confirmation did not permit ordered analysis")
    confirmed = transition.contract
    final_validation = validate_audit_contract(confirmed, profile)
    if (
        not final_validation.valid
        or not analysis_is_permitted(final_validation)
        or not final_validation.g1_eligible
        or final_validation.canonical_contract_sha256
        != transition.validation.canonical_contract_sha256
        or final_validation.contract_id != confirmed.contract_id
    ):
        raise ValueError("public demo confirmed contract failed deterministic revalidation")
    return confirmed, transition.validation.canonical_contract_sha256


def _validate_canonical_results(result: FillProtocolActionResult) -> None:
    selection_payload = result.riec.selection.to_canonical_dict()
    protocol_payload = result.protocols.to_canonical_dict()
    action_payload = result.action.to_canonical_dict()
    if RiecSelection.model_validate(selection_payload) != result.riec.selection:
        raise ValueError("RIEC selection canonical round trip failed")
    if ProtocolResult.model_validate(protocol_payload) != result.protocols:
        raise ValueError("protocol result canonical round trip failed")
    if ActionDecision.model_validate(action_payload) != result.action:
        raise ValueError("action decision canonical round trip failed")
    _validate_schema("riec_selection", selection_payload)
    _validate_schema("protocol_result", protocol_payload)
    _validate_schema("action_decision", action_payload)


def _validate_schema(logical_name: str, payload: Mapping[str, object]) -> None:
    schema = load_schema_registry().lookup(logical_name).validation_schema()
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(dict(payload))


def _validate_unfinalized_chain(
    result: FillProtocolActionResult,
    builder: EvidenceLedgerBuilder,
) -> None:
    if builder.finalized or tuple(item.component for item in builder.items) != (
        EvidenceComponent.RIEC,
        EvidenceComponent.PROTOCOL,
        EvidenceComponent.ACTION,
    ):
        raise ValueError("public demo evidence builder does not contain the fixed three-item chain")
    for item in builder.items:
        verify_evidence_item(item)
    riec_id = result.riec.evidence_item.evidence_id
    protocol_id = result.protocol_evidence.evidence_id
    action_id = result.action_evidence.evidence_id
    if (
        result.riec.selection.evidence_ids != (riec_id,)
        or any(entry.evidence_ids != (protocol_id,) for entry in result.protocols.results)
        or result.protocol_evidence.parent_evidence_ids != (riec_id,)
        or set(result.action_evidence.parent_evidence_ids) != {riec_id, protocol_id}
        or set(result.action.evidence_ids) != {riec_id, protocol_id, action_id}
    ):
        raise ValueError("public demo canonical artifacts do not match the evidence chain")


def _validate_finalized_chain(
    result: FillProtocolActionResult,
    ledger: EvidenceLedger,
    graph: ProvenanceGraph,
) -> None:
    riec_id = result.riec.evidence_item.evidence_id
    protocol_id = result.protocol_evidence.evidence_id
    action_id = result.action_evidence.evidence_id
    if len(ledger.items) != 3:
        raise ValueError("public demo finalized ledger must contain exactly three items")
    if (
        graph.direct_ancestors(riec_id) != ()
        or graph.direct_ancestors(protocol_id) != (riec_id,)
        or set(graph.direct_ancestors(action_id)) != {riec_id, protocol_id}
        or set(graph.ancestors(action_id)) != {riec_id, protocol_id}
    ):
        raise ValueError("public demo evidence provenance is not the fixed acyclic chain")


def _recorded_scenario_summary(
    definition: ScenarioDefinition,
    result: FillProtocolActionResult,
    ledger: EvidenceLedger,
    *,
    dataset_sha256: str,
    contract_sha256: str,
) -> RecordedScenarioSummary:
    entries = {entry.protocol_id: entry for entry in result.protocols.results}
    expected_ids = {
        ProtocolId.D0_MEAN_DIAGNOSTIC,
        ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE,
        ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL,
        ProtocolId.H3_STUDENT_T_RESIDUAL_TAIL,
        ProtocolId.U1_GROUP_BOOTSTRAP_BOUND,
        ProtocolId.G1_ORDERED_STABILITY_SCREEN,
        ProtocolId.G2_EVIDENCE_SUFFICIENCY_GATE,
    }
    if set(entries) != expected_ids:
        raise ValueError("public demo protocol bundle is incomplete")
    h1 = entries[ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE]
    h2 = entries[ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL]
    h3 = entries[ProtocolId.H3_STUDENT_T_RESIDUAL_TAIL]
    u1 = entries[ProtocolId.U1_GROUP_BOOTSTRAP_BOUND]
    g2 = entries[ProtocolId.G2_EVIDENCE_SUFFICIENCY_GATE]
    selection = result.riec.selection
    action = result.action
    if selection.raw_numeric_winner is None or not action.reason_codes:
        raise ValueError("public demo result has no canonical winner or decisive reason")
    if action.safe_headroom.unit != "mL":
        raise ValueError("public demo action unit changed")

    evidence_chain = tuple(
        {
            "component": item.component.value,
            "evidence_id": item.evidence_id,
            "content_sha256": item.content_sha256,
            "parent_evidence_ids": item.parent_evidence_ids,
        }
        for item in ledger.items
    )
    pilot = action.pilot_reference
    payload: dict[str, object] = {
        "scenario_id": definition.scenario_id,
        "scenario_version": definition.scenario_version,
        "dataset_sha256": dataset_sha256,
        "row_count": definition.design.row_count,
        "deployment_group_count": definition.design.deployment_group_count,
        "product_count": definition.design.product_count,
        "rows_per_product": definition.design.rows_per_product,
        "expected_tail_count_per_product": definition.design.expected_tail_count_per_product,
        "policy_profile_id": definition.policy.profile_id,
        "contract_id": action.contract_id,
        "contract_sha256": contract_sha256,
        "riec_winner": selection.raw_numeric_winner,
        "riec_runner_up": selection.runner_up,
        "riec_near_tie": action.conflict.near_tie,
        "equivalence_set": selection.equivalence_set,
        "h1": _protocol_display(h1),
        "h2": _protocol_display(h2),
        "h3": _protocol_display(h3),
        "u1": {
            "protocol_id": u1.protocol_id,
            "status": u1.status,
            "lower_bound": u1.uncertainty.lower if u1.uncertainty is not None else None,
            "requested_replicates": _integer_metric(u1, "requested_replicates"),
            "successful_replicates": _integer_metric(u1, "successful_replicates"),
            "failed_replicates": _integer_metric(u1, "failed_replicates"),
            "seed": _integer_metric(u1, "bootstrap_seed"),
        },
        "g1_state": DemoG1State(action.gates.ordered_stability.value),
        "g2": {
            "protocol_id": g2.protocol_id,
            "status": g2.status,
            "action_supported": action.gates.evidence_sufficient,
            "minimum_product_rows": _integer_metric(g2, "minimum_product_rows"),
            "minimum_product_groups": _integer_metric(g2, "minimum_product_groups"),
            "alpha": _number_metric(g2, "alpha"),
            "expected_tail_count": _number_metric(g2, "expected_tail_count"),
            "min_expected_tail_count": _number_metric(g2, "min_expected_tail_count"),
        },
        "protocol_spread": action.conflict.protocol_spread,
        "protocol_conflict": action.conflict.material_protocol_conflict,
        "action_state": action.state,
        "decisive_reason": action.reason_codes[0],
        "pilot_min": None if pilot is None else pilot.lower,
        "pilot_max": None if pilot is None else pilot.upper,
        "unit": action.safe_headroom.unit,
        "riec_evidence_id": result.riec.evidence_item.evidence_id,
        "protocol_evidence_id": result.protocol_evidence.evidence_id,
        "action_evidence_id": result.action_evidence.evidence_id,
        "evidence_chain": evidence_chain,
        "riec_selection_canonical_sha256_normalized_run_id": _normalized_run_hash(selection),
        "protocol_result_canonical_sha256_normalized_run_id": _normalized_run_hash(
            result.protocols
        ),
        "action_decision_canonical_sha256_normalized_run_id": _normalized_run_hash(action),
    }
    return seal_record(payload)


def _protocol_display(entry: ProtocolResultEntry) -> ProtocolDisplay:
    return ProtocolDisplay.model_validate(
        {
            "protocol_id": entry.protocol_id,
            "status": entry.status,
            "value": entry.point_estimate,
            "lower_bound": (entry.uncertainty.lower if entry.uncertainty is not None else None),
            "unit": entry.unit,
        }
    )


def _metric(entry: ProtocolResultEntry, name: str) -> object:
    for metric in entry.metrics:
        if metric.name == name:
            return metric.value
    raise ValueError("required public protocol metric is missing")


def _integer_metric(entry: ProtocolResultEntry, name: str) -> int:
    value = _metric(entry, name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("required public protocol count metric is invalid")
    return value


def _number_metric(entry: ProtocolResultEntry, name: str) -> int | float:
    value = _metric(entry, name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("required public protocol numeric metric is invalid")
    return value


def _normalized_run_hash(value: RiecSelection | ProtocolResult | ActionDecision) -> str:
    payload = value.to_canonical_dict()
    payload["run_id"] = _NORMALIZED_RUN_ID
    return canonical_sha256(payload)


def _error(
    code: str,
    *,
    stage: ErrorStage,
    error_class: ErrorClass,
    message: str,
    recoverable: bool,
    user_action: str,
) -> ErrorEnvelope:
    identity = f"{stage.value}:{error_class.value}:{code}".encode("utf-8")
    return ErrorEnvelope.model_validate(
        {
            "schema_version": "1.0.0",
            "error_id": f"ERR-{hashlib.sha256(identity).hexdigest()[:12].upper()}",
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


__all__ = ["build_recorded_summary", "run_public_demo_scenario"]
