from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, cast

import pytest
from pydantic import ValidationError

from riec_guard.contract.canonicalize import (
    CONFIRMATION_FIELD_ORDER,
    ContractCanonicalizationError,
    canonicalize_audit_contract,
    compute_contract_hash,
)
from riec_guard.contract.models import (
    AuditContract,
    CandidateRegistry,
    ConfirmedBy,
    ConfirmationStatus,
    ContractValidationCode,
    DatasetProfile,
)
from riec_guard.contract.validator import (
    confirm_audit_contract,
    reject_audit_contract,
    validate_audit_contract,
)
from riec_guard.evidence.ids import (
    CanonicalJsonError,
    EvidenceError,
    EvidenceErrorCode,
    canonical_json_bytes,
    canonical_sha256,
    create_evidence_item,
)
from riec_guard.evidence.ledger import EvidenceLedgerBuilder
from riec_guard.evidence.models import EvidenceItem
from riec_guard.evidence.provenance import validate_provenance_graph
from riec_guard.riec.registry import (
    FROZEN_CANDIDATE_IDS,
    RegistryConfigError,
    RegistryErrorCode,
    load_candidate_registry,
    load_run_registry_snapshot,
    verify_config_snapshot_hashes,
)
from riec_guard.settings import RuntimeSettings, SettingsValidationError
from riec_guard.telemetry.manifest import (
    ManifestError,
    ManifestErrorCode,
    RunManifestBuilder,
    manifest_registries_from_snapshot,
    manifest_sha256,
    render_checksum_inventory,
    verify_checksum_inventory,
)
from riec_guard.telemetry.models import RunManifest, RunStatus

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_ROOT = REPOSITORY_ROOT / "schemas" / "examples"
CONFIG_ROOT = REPOSITORY_ROOT / "configs"
RUN_ID = "RUN-ABCDEF123456"
STARTED_AT = "2026-07-19T00:00:00Z"
FINISHED_AT = "2026-07-19T00:01:00Z"
INPUT_HASH = "1" * 64
CONTRACT_HASH = "2" * 64
SOURCE_HASH = "3" * 64
ACTION_ENGINE_VERSION = "1.0.0"


def _json_example(name: str) -> dict[str, Any]:
    value = json.loads((EXAMPLE_ROOT / name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


PROFILE = DatasetProfile.model_validate(_json_example("dataset_profile.example.json"))


def _ready_contract_data() -> dict[str, Any]:
    value = _json_example("audit_contract.example.json")
    value["confirmation"] = {
        "status": "draft",
        "confirmed_fields": list(CONFIRMATION_FIELD_ORDER),
        "confirmed_at": None,
        "confirmed_by": "none",
    }
    return value


def _ready_contract() -> AuditContract:
    return canonicalize_audit_contract(_ready_contract_data())


def _confirmed_contract() -> AuditContract:
    result = confirm_audit_contract(
        _ready_contract(),
        PROFILE,
        confirmed_fields=CONFIRMATION_FIELD_ORDER,
        confirmed_by=ConfirmedBy.USER,
        confirmed_at=STARTED_AT,
    )
    assert result.transitioned
    return result.contract


def _set_path(value: dict[str, Any], path: str, replacement: object) -> dict[str, Any]:
    result = copy.deepcopy(value)
    current = result
    parts = path.split(".")
    for part in parts[:-1]:
        child = current[part]
        assert isinstance(child, dict)
        current = child
    current[parts[-1]] = replacement
    return result


def _blocking_codes(report: object) -> set[ContractValidationCode]:
    blocking = getattr(report, "blocking_errors")
    return {issue.code for issue in blocking}


DECISION_CRITICAL_REPLACEMENTS: tuple[tuple[str, object], ...] = (
    ("column_mapping.quantity.column", "quantity_alternate"),
    ("column_mapping.deployment_group.column", "batch_alternate"),
    ("measurement.quantity_semantics", "mass"),
    ("measurement.unit", "L"),
    ("grouping.deployment_group_columns", ["shift_id"]),
    ("ordering.status", "unavailable"),
    ("ordering.time_column", "row_sequence"),
    ("policy.nominal_quantity", 251.0),
    ("policy.lower_limit", 249.0),
    ("policy.alpha", 0.02),
    ("policy.minimum_actionable_shift", 0.2),
    ("policy.maximum_screening_shift", 1.5),
    ("policy.protocol_spread_tolerance", 0.6),
    ("riec.c", 2.0),
    ("privacy.classification", "public_user_upload"),
)


@pytest.mark.parametrize("field_path", CONFIRMATION_FIELD_ORDER)
def test_f01_any_blocking_unresolved_field_prevents_confirmation(field_path: str) -> None:
    value = _ready_contract_data()
    value["unresolved_fields"] = [
        {
            "field_path": field_path,
            "severity": "blocking",
            "question": "Confirm this decision-critical value.",
        }
    ]
    contract = canonicalize_audit_contract(value)
    result = confirm_audit_contract(
        contract,
        PROFILE,
        confirmed_fields=CONFIRMATION_FIELD_ORDER,
        confirmed_by=ConfirmedBy.USER,
        confirmed_at=STARTED_AT,
    )
    assert not result.transitioned
    assert not result.validation.analysis_permitted
    assert ContractValidationCode.CONTRACT_UNRESOLVED_BLOCKING in _blocking_codes(result.validation)


def test_f02_unconfirmed_gpt_decision_assumption_prevents_confirmation() -> None:
    value = _ready_contract_data()
    value["assumptions"] = [
        {
            "assumption_id": "ASM-001",
            "text": "A decision-critical value was inferred.",
            "source": "gpt_inference",
            "user_confirmed": False,
        }
    ]
    result = confirm_audit_contract(
        canonicalize_audit_contract(value),
        PROFILE,
        confirmed_fields=CONFIRMATION_FIELD_ORDER,
        confirmed_by=ConfirmedBy.USER,
        confirmed_at=STARTED_AT,
    )
    assert not result.transitioned
    assert ContractValidationCode.CONTRACT_ASSUMPTION_UNCONFIRMED in _blocking_codes(
        result.validation
    )


def test_f03_status_mutation_alone_never_permits_analysis() -> None:
    value = _ready_contract_data()
    value["confirmation"] = {
        "status": "confirmed",
        "confirmed_fields": [],
        "confirmed_at": STARTED_AT,
        "confirmed_by": "user",
    }
    report = validate_audit_contract(canonicalize_audit_contract(value), PROFILE)
    assert not report.analysis_permitted
    assert ContractValidationCode.CONTRACT_CONFIRMATION_INCOMPLETE in _blocking_codes(report)


@pytest.mark.parametrize("missing_field", CONFIRMATION_FIELD_ORDER)
def test_f04_missing_one_required_confirmed_field_prevents_analysis(
    missing_field: str,
) -> None:
    fields = tuple(field for field in CONFIRMATION_FIELD_ORDER if field != missing_field)
    result = confirm_audit_contract(
        _ready_contract(),
        PROFILE,
        confirmed_fields=fields,
        confirmed_by=ConfirmedBy.USER,
        confirmed_at=STARTED_AT,
    )
    assert not result.transitioned
    assert not result.validation.analysis_permitted
    assert ContractValidationCode.CONTRACT_CONFIRMATION_INCOMPLETE in _blocking_codes(
        result.validation
    )


@pytest.mark.parametrize(("field_path", "replacement"), DECISION_CRITICAL_REPLACEMENTS)
def test_f05_changing_any_decision_critical_field_changes_contract_identity(
    field_path: str,
    replacement: object,
) -> None:
    assert {path for path, _ in DECISION_CRITICAL_REPLACEMENTS} == set(CONFIRMATION_FIELD_ORDER)
    baseline = _ready_contract()
    changed = canonicalize_audit_contract(
        _set_path(baseline.to_canonical_dict(), field_path, replacement)
    )
    assert compute_contract_hash(changed) != compute_contract_hash(baseline)


@pytest.mark.parametrize("timestamp_field", ["created_at", "confirmation.confirmed_at"])
def test_f06_excluded_runtime_timestamps_do_not_change_contract_identity(
    timestamp_field: str,
) -> None:
    baseline = _ready_contract() if timestamp_field == "created_at" else _confirmed_contract()
    changed = canonicalize_audit_contract(
        _set_path(
            baseline.to_canonical_dict(),
            timestamp_field,
            "2027-01-01T00:00:00Z",
        )
    )
    assert compute_contract_hash(changed) == compute_contract_hash(baseline)


def test_f07_confirmed_contract_cannot_transition_back_to_draft() -> None:
    confirmed = _confirmed_contract()
    result = reject_audit_contract(confirmed, PROFILE)
    assert not result.transitioned
    assert result.contract.confirmation.status is ConfirmationStatus.CONFIRMED
    assert ContractValidationCode.CONTRACT_INVALID_TRANSITION in _blocking_codes(result.validation)


def test_f08_rejected_contract_is_never_analysis_permitted() -> None:
    result = reject_audit_contract(_ready_contract(), PROFILE)
    assert result.transitioned
    assert result.contract.confirmation.status is ConfirmationStatus.REJECTED
    assert not result.validation.analysis_permitted


def test_f09_random_row_fallback_can_never_become_valid() -> None:
    value = _ready_contract_data()
    value["grouping"]["no_random_row_fallback"] = False
    report = validate_audit_contract(value, PROFILE)
    assert not report.valid
    assert not report.analysis_permitted
    assert ContractValidationCode.CONTRACT_GROUP_UNCONFIRMED in _blocking_codes(report)


def test_f10_tie_break_column_order_is_meaningful_and_hash_sensitive() -> None:
    first = canonicalize_audit_contract(
        _set_path(
            _ready_contract_data(),
            "ordering.tie_break_columns",
            ["row_sequence", "stream_id"],
        )
    )
    second = canonicalize_audit_contract(
        _set_path(
            _ready_contract_data(),
            "ordering.tie_break_columns",
            ["stream_id", "row_sequence"],
        )
    )
    assert first.ordering.tie_break_columns != second.ordering.tie_break_columns
    assert compute_contract_hash(first) != compute_contract_hash(second)


def test_f11_confirmed_field_order_is_set_like_and_hash_invariant() -> None:
    first = canonicalize_audit_contract(_ready_contract_data())
    value = _ready_contract_data()
    value["confirmation"]["confirmed_fields"] = list(reversed(CONFIRMATION_FIELD_ORDER))
    second = canonicalize_audit_contract(value)
    assert first.confirmation.confirmed_fields == second.confirmation.confirmed_fields
    assert compute_contract_hash(first) == compute_contract_hash(second)


def test_f12_composite_grouping_is_not_fabricated_from_incomplete_profile_evidence() -> None:
    value = _ready_contract_data()
    value["grouping"]["deployment_group_columns"] = ["batch_id", "shift_id"]
    contract = canonicalize_audit_contract(value)
    profile_payload = PROFILE.to_canonical_dict()
    columns = cast(list[dict[str, Any]], profile_payload["column_profiles"])
    profile_payload["column_profiles"] = [
        column for column in columns if column["name"] != "shift_id"
    ]
    incomplete_profile = DatasetProfile.model_validate(profile_payload)
    report = validate_audit_contract(contract, incomplete_profile)
    assert contract.grouping.deployment_group_columns == ("batch_id", "shift_id")
    assert not report.valid and not report.analysis_permitted
    assert ContractValidationCode.CONTRACT_COLUMN_NOT_FOUND in _blocking_codes(report)


RegistryMutation = Callable[[dict[str, Any]], None]
ShadowOperation = Literal["candidate", "run"]


@pytest.fixture(scope="module")
def stage1_shadow_repository(tmp_path_factory: pytest.TempPathFactory) -> Path:
    shadow = tmp_path_factory.mktemp("stage1-shadow") / "shadow-repository"
    shutil.copytree(
        REPOSITORY_ROOT / "src" / "riec_guard",
        shadow / "src" / "riec_guard",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    shutil.copytree(CONFIG_ROOT, shadow / "configs")
    shutil.copytree(REPOSITORY_ROOT / "schemas", shadow / "schemas")
    return shadow


def _mutate_shadow_candidate(shadow: Path, mutation: RegistryMutation) -> None:
    path = shadow / "configs" / "candidates.fill.v1.json"
    payload = json.loads((CONFIG_ROOT / "candidates.fill.v1.json").read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    mutation(payload)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _shadow_registry_probe(shadow: Path, operation: ShadowOperation) -> dict[str, Any]:
    script = """
import json
import sys

from riec_guard.riec.registry import (
    RegistryConfigError,
    load_candidate_registry,
    load_run_registry_snapshot,
)

try:
    if sys.argv[1] == "candidate":
        snapshot = load_candidate_registry()
        result = {"status": "ok", "record": snapshot.provenance_record()}
    else:
        snapshot = load_run_registry_snapshot()
        result = {"status": "ok", "records": snapshot.provenance_records()}
except RegistryConfigError as error:
    result = {"status": "error", "code": error.code.value}
print(json.dumps(result, sort_keys=True))
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(shadow / "src")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [sys.executable, "-c", script, operation],
        cwd=shadow,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert isinstance(result, dict)
    return result


def _candidate_list(payload: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = payload["candidates"]
    assert isinstance(candidates, list)
    return cast(list[dict[str, Any]], candidates)


@pytest.mark.parametrize("candidate_id", FROZEN_CANDIDATE_IDS)
def test_f13_removing_any_m0_to_m6_candidate_is_rejected(
    stage1_shadow_repository: Path,
    candidate_id: str,
) -> None:
    shadow = stage1_shadow_repository

    def remove_candidate(payload: dict[str, Any]) -> None:
        candidates = _candidate_list(payload)
        payload["candidates"] = [
            candidate for candidate in candidates if candidate["candidate_id"] != candidate_id
        ]

    _mutate_shadow_candidate(shadow, remove_candidate)
    result = _shadow_registry_probe(shadow, "candidate")
    assert result == {
        "status": "error",
        "code": RegistryErrorCode.REGISTRY_FROZEN_SET_MISMATCH.value,
    }


def test_f14_adding_an_eighth_candidate_is_rejected(
    stage1_shadow_repository: Path,
) -> None:
    shadow = stage1_shadow_repository

    def add_candidate(payload: dict[str, Any]) -> None:
        candidates = _candidate_list(payload)
        extra = copy.deepcopy(candidates[-1])
        extra["candidate_id"] = "M7_dynamic_search"
        candidates.append(extra)

    _mutate_shadow_candidate(shadow, add_candidate)
    result = _shadow_registry_probe(shadow, "candidate")
    assert result["code"] == RegistryErrorCode.REGISTRY_FROZEN_SET_MISMATCH.value


def test_f15_reordering_candidates_is_rejected(
    stage1_shadow_repository: Path,
) -> None:
    shadow = stage1_shadow_repository

    def reorder_candidates(payload: dict[str, Any]) -> None:
        candidates = _candidate_list(payload)
        candidates[1], candidates[2] = candidates[2], candidates[1]

    _mutate_shadow_candidate(shadow, reorder_candidates)
    result = _shadow_registry_probe(shadow, "candidate")
    assert result["code"] == RegistryErrorCode.REGISTRY_FROZEN_SET_MISMATCH.value


def test_f16_changing_the_candidate_baseline_is_rejected(
    stage1_shadow_repository: Path,
) -> None:
    shadow = stage1_shadow_repository
    _mutate_shadow_candidate(
        shadow,
        lambda payload: payload.update(baseline_candidate_id="M1_product"),
    )
    result = _shadow_registry_probe(shadow, "candidate")
    assert result["code"] == RegistryErrorCode.REGISTRY_BASELINE_INVALID.value


NONCANDIDATE_OBJECTS: tuple[tuple[str, str], ...] = (
    ("H1_group_empirical_quantile", "headroom_protocol"),
    ("H2_gaussian_residual_tail", "headroom_protocol"),
    ("H3_student_t_residual_tail", "headroom_protocol"),
    ("U1_group_bootstrap_bound", "uncertainty_procedure"),
    ("G1_ordered_stability_screen", "stability_gate"),
    ("G2_evidence_sufficiency_gate", "sufficiency_gate"),
)


@pytest.mark.parametrize(("object_id", "category"), NONCANDIDATE_OBJECTS)
def test_f17_protocols_and_gates_cannot_enter_candidate_ranking(
    stage1_shadow_repository: Path,
    object_id: str,
    category: str,
) -> None:
    shadow = stage1_shadow_repository

    def insert_noncandidate(payload: dict[str, Any]) -> None:
        _candidate_list(payload).append({"object_id": object_id, "category": category})

    _mutate_shadow_candidate(shadow, insert_noncandidate)
    result = _shadow_registry_probe(shadow, "candidate")
    assert result["code"] == RegistryErrorCode.REGISTRY_CROSS_TYPE_INSERTION.value


def test_f18_changing_a_production_registry_value_changes_canonical_hash() -> None:
    snapshot = load_candidate_registry()
    payload = snapshot.payload.to_canonical_dict()
    candidates = cast(list[dict[str, Any]], payload["candidates"])
    requirements = cast(dict[str, object], candidates[0]["feasibility_requirements"])
    requirements["min_rows"] = 81
    changed = CandidateRegistry.model_validate(payload)
    assert canonical_sha256(snapshot.payload) == snapshot.canonical_json_sha256
    assert canonical_sha256(changed) != snapshot.canonical_json_sha256


def test_f19_whitespace_only_json_changes_file_hash_not_canonical_hash() -> None:
    snapshot = load_candidate_registry()
    payload = snapshot.payload.to_canonical_dict()
    compact = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    spaced = (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    assert hashlib.sha256(compact).hexdigest() != hashlib.sha256(spaced).hexdigest()
    compact_model = CandidateRegistry.model_validate(json.loads(compact))
    spaced_model = CandidateRegistry.model_validate(json.loads(spaced))
    assert canonical_sha256(compact_model) == canonical_sha256(spaced_model)
    assert canonical_sha256(compact_model) == snapshot.canonical_json_sha256


def test_f20_unfrozen_configuration_cannot_produce_run_snapshot(
    stage1_shadow_repository: Path,
) -> None:
    shadow = stage1_shadow_repository
    _mutate_shadow_candidate(
        shadow,
        lambda payload: payload.update(frozen_before_ranking=False),
    )
    result = _shadow_registry_probe(shadow, "run")
    assert result["code"] == RegistryErrorCode.REGISTRY_NOT_FROZEN.value


def _manifest_builder(
    tmp_path: Path,
    *,
    registries: object | None = None,
    store: bool = False,
    raw_rows_sent_to_gpt: bool = False,
    direct_identifiers_sent_to_gpt: bool = False,
) -> tuple[RunManifestBuilder, Path]:
    artifact_root = tmp_path / RUN_ID / "artifacts"
    artifact_root.mkdir(parents=True, exist_ok=True)
    snapshot = load_run_registry_snapshot()
    builder = RunManifestBuilder(
        run_id=RUN_ID,
        mode="public_builtin",
        started_at=STARTED_AT,
        code={
            "repository": "riec-guard",
            "commit_sha": "a" * 40,
            "dirty": False,
            "build_week_delta_version": "1.0.0",
        },
        environment={
            "python": "3.12.13",
            "platform": "Darwin arm64",
            "dependency_lock_sha256": "4" * 64,
        },
        contract={
            "contract_id": "AC-ABCDEF123456",
            "sha256": CONTRACT_HASH,
            "schema_version": "1.0.0",
            "confirmation_status": "confirmed",
        },
        registry_snapshot=snapshot,
        action_engine_version=ACTION_ENGINE_VERSION,
        registries=registries,  # type: ignore[arg-type]
        randomness={
            "global_seed": 20260718,
            "bootstrap_seed": 20260718,
            "bootstrap_replicates": 200,
        },
        configured_model="gpt-5.6-sol",
        artifact_root=artifact_root,
        storage_root_class="public_ephemeral",
        store=store,
        raw_rows_sent_to_gpt=raw_rows_sent_to_gpt,
        direct_identifiers_sent_to_gpt=direct_identifiers_sent_to_gpt,
    )
    return builder, artifact_root


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("id", "other-candidate-registry.v1"),
        ("version", "1.0.1"),
        ("sha256", "0" * 64),
    ],
)
def test_f21_valid_looking_manifest_config_mismatch_fails_closed(
    tmp_path: Path,
    field: str,
    replacement: str,
) -> None:
    snapshot = load_run_registry_snapshot()
    payload = manifest_registries_from_snapshot(
        snapshot,
        action_engine_version=ACTION_ENGINE_VERSION,
    ).to_canonical_dict()
    candidate = cast(dict[str, object], payload["candidate_registry"])
    candidate[field] = replacement
    with pytest.raises(ManifestError) as caught:
        _manifest_builder(tmp_path, registries=payload)
    assert caught.value.code is ManifestErrorCode.MANIFEST_REGISTRY_INVALID


def test_f22_unregistered_config_file_is_never_auto_discovered(
    stage1_shadow_repository: Path,
) -> None:
    shadow = stage1_shadow_repository
    _mutate_shadow_candidate(shadow, lambda payload: None)
    (shadow / "configs" / "unregistered-extra.json").write_text(
        '{"schema_version":"1.0.0"}\n',
        encoding="utf-8",
    )
    result = _shadow_registry_probe(shadow, "run")
    assert result["status"] == "ok"
    records = cast(list[dict[str, object]], result["records"])
    assert len(records) == 5
    assert "unregistered-extra" not in {record["logical_id"] for record in records}


def _evidence_fields(**changes: object) -> dict[str, object]:
    fields: dict[str, object] = {
        "component": "PROFILE",
        "kind": "statistic",
        "status": "ok",
        "statement": "The public aggregate contains three rows.",
        "value": {"n_rows": 3, "mean": 1.25},
        "unit": None,
        "source_refs": [
            {
                "artifact_id": "fixture.v1",
                "artifact_sha256": SOURCE_HASH,
                "locator": "public synthetic fixture",
            }
        ],
        "parent_evidence_ids": [],
        "input_sha256": INPUT_HASH,
        "contract_sha256": CONTRACT_HASH,
        "implementation_version": "1.0.0",
        "created_at": STARTED_AT,
    }
    fields.update(changes)
    return fields


def _evidence_item(**changes: object) -> EvidenceItem:
    return create_evidence_item(**_evidence_fields(**changes))  # type: ignore[arg-type]


def _append_evidence(builder: EvidenceLedgerBuilder, **changes: object):
    return builder.append_new(**_evidence_fields(**changes))  # type: ignore[arg-type]


def test_f23_changing_evidence_content_changes_evidence_id() -> None:
    first = _evidence_item()
    second = _evidence_item(statement="The public aggregate contains four rows.")
    assert first.content_sha256 != second.content_sha256
    assert first.evidence_id != second.evidence_id


def test_f24_changing_only_evidence_timestamp_does_not_change_id() -> None:
    first = _evidence_item(created_at=STARTED_AT)
    second = _evidence_item(created_at="2027-01-01T00:00:00Z")
    assert first.content_sha256 == second.content_sha256
    assert first.evidence_id == second.evidence_id


def test_f25_missing_parent_evidence_fails() -> None:
    builder = EvidenceLedgerBuilder(RUN_ID)
    _append_evidence(builder, parent_evidence_ids=["EV-SYSTEM-AAAAAAAAAAAA"])
    with pytest.raises(EvidenceError) as caught:
        builder.finalize()
    assert caught.value.code is EvidenceErrorCode.EVIDENCE_PARENT_NOT_FOUND


def test_f26_cyclic_provenance_fails() -> None:
    left_id = "EV-SYSTEM-AAAAAAAAAAAA"
    right_id = "EV-SYSTEM-BBBBBBBBBBBB"
    left = _evidence_item().model_copy(
        update={
            "evidence_id": left_id,
            "content_sha256": "0" * 64,
            "parent_evidence_ids": (right_id,),
        }
    )
    right = _evidence_item().model_copy(
        update={
            "evidence_id": right_id,
            "content_sha256": "0" * 64,
            "parent_evidence_ids": (left_id,),
        }
    )
    with pytest.raises(EvidenceError) as caught:
        validate_provenance_graph((left, right))
    assert caught.value.code is EvidenceErrorCode.EVIDENCE_GRAPH_CYCLE


def test_f27_cross_run_evidence_linking_fails() -> None:
    source = EvidenceLedgerBuilder("RUN-AAAAAAAAAAAA")
    foreign = _append_evidence(source)
    target = EvidenceLedgerBuilder("RUN-BBBBBBBBBBBB")
    with pytest.raises(EvidenceError) as caught:
        target.append(foreign)
    assert caught.value.code is EvidenceErrorCode.EVIDENCE_RUN_MISMATCH
    assert target.items == ()


def _prepared_manifest_builder(tmp_path: Path, *, classification: str = "public_synthetic"):
    builder, artifact_root = _manifest_builder(tmp_path)
    builder.register_input(
        artifact_id="fixture.v1",
        sha256=INPUT_HASH,
        classification=classification,
        row_count=3,
    )
    (artifact_root / "result.json").write_text("{}", encoding="utf-8")
    builder.register_artifact(
        artifact_id="result.json",
        relative_path="result.json",
        media_type="application/json",
        public_safe=True,
    )
    return builder, artifact_root


def test_f28_tampered_artifact_bytes_fail_checksum_verification(tmp_path: Path) -> None:
    builder, artifact_root = _prepared_manifest_builder(tmp_path)
    inventory = render_checksum_inventory(builder.artifacts)
    (artifact_root / "result.json").write_text('{"tampered":true}', encoding="utf-8")
    with pytest.raises(ManifestError) as caught:
        verify_checksum_inventory(artifact_root, inventory, builder.artifacts)
    assert caught.value.code is ManifestErrorCode.CHECKSUM_VERIFICATION_FAILED


def test_f29_gpt_store_true_is_always_rejected(tmp_path: Path) -> None:
    with pytest.raises(ManifestError) as caught:
        _manifest_builder(tmp_path, store=True)
    assert caught.value.code is ManifestErrorCode.MANIFEST_GPT_INVALID


@pytest.mark.parametrize(
    ("raw_rows", "direct_identifiers"),
    [(True, False), (False, True)],
)
def test_f30_either_gpt_privacy_flag_true_is_always_rejected(
    tmp_path: Path,
    raw_rows: bool,
    direct_identifiers: bool,
) -> None:
    with pytest.raises(ManifestError) as caught:
        _manifest_builder(
            tmp_path,
            raw_rows_sent_to_gpt=raw_rows,
            direct_identifiers_sent_to_gpt=direct_identifiers,
        )
    assert caught.value.code is ManifestErrorCode.MANIFEST_MODE_PRIVACY_MISMATCH


def test_f31_private_input_in_public_mode_always_fails(tmp_path: Path) -> None:
    builder, _ = _prepared_manifest_builder(tmp_path, classification="private_industrial")
    builder.start().complete(finished_at=FINISHED_AT)
    with pytest.raises(ManifestError) as caught:
        builder.finalize()
    assert caught.value.code is ManifestErrorCode.MANIFEST_MODE_PRIVACY_MISMATCH


def test_f32_terminal_manifest_cannot_be_forged_by_direct_status_mutation(
    tmp_path: Path,
) -> None:
    builder, _ = _prepared_manifest_builder(tmp_path)
    builder._status = RunStatus.COMPLETED
    builder._finished_at = FINISHED_AT
    with pytest.raises(ManifestError) as caught:
        builder.finalize()
    assert caught.value.code is ManifestErrorCode.MANIFEST_INVALID_TRANSITION


@pytest.mark.parametrize("nonfinite", [math.nan, math.inf, -math.inf])
def test_f33_nonfinite_values_never_enter_contract_evidence_or_manifest_hashing(
    nonfinite: float,
) -> None:
    with pytest.raises(ContractCanonicalizationError):
        canonicalize_audit_contract(_set_path(_ready_contract_data(), "policy.alpha", nonfinite))
    with pytest.raises(EvidenceError) as evidence_error:
        _evidence_item(value={"mean": nonfinite})
    assert evidence_error.value.code is EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT

    manifest = RunManifest.model_validate(_json_example("run_manifest.example.json"))
    bad_call = manifest.gpt.calls[1].model_copy(update={"latency_ms": nonfinite})
    bad_gpt = manifest.gpt.model_copy(
        update={"calls": (manifest.gpt.calls[0], bad_call, *manifest.gpt.calls[2:])}
    )
    bad_manifest = manifest.model_copy(update={"gpt": bad_gpt})
    with pytest.raises(ValueError, match="non-finite"):
        manifest_sha256(bad_manifest)


@pytest.mark.parametrize(
    "unsupported",
    [object(), b"bytes", {"set-member"}, Path("logical/path")],
)
def test_f34_unsupported_python_objects_never_enter_canonical_hashing(
    unsupported: object,
) -> None:
    with pytest.raises(CanonicalJsonError):
        canonical_json_bytes(unsupported)


@pytest.mark.parametrize("private_inside_public", [True, False])
def test_nested_public_private_runtime_roots_are_rejected(
    tmp_path: Path,
    private_inside_public: bool,
) -> None:
    outer = tmp_path / "outer"
    inner = outer / "inner"
    ephemeral_root, private_root = (outer, inner) if private_inside_public else (inner, outer)
    with pytest.raises(SettingsValidationError, match="different roots"):
        RuntimeSettings.private_local(
            ephemeral_root=ephemeral_root,
            private_data_root=private_root,
        )


@pytest.mark.parametrize("mutation", ["raw_rows", "direct_identifiers"])
def test_canonical_profile_payload_rejects_raw_rows_and_direct_identifiers(
    mutation: str,
) -> None:
    payload = PROFILE.to_canonical_dict()
    if mutation == "raw_rows":
        payload["raw_rows"] = [["synthetic-value"]]
    else:
        privacy = cast(dict[str, object], payload["privacy_redaction"])
        privacy["direct_identifiers_included"] = True
    with pytest.raises(ValidationError):
        DatasetProfile.model_validate(payload)


@pytest.mark.parametrize(
    "unsafe_value",
    [
        {"raw_rows": [[1.0]]},
        {"note": "synthetic-person" + "@" + "example.invalid"},
    ],
)
def test_canonical_ledger_payload_rejects_raw_rows_and_direct_identifiers(
    unsafe_value: dict[str, object],
) -> None:
    with pytest.raises(EvidenceError) as caught:
        _evidence_item(value=unsafe_value)
    assert caught.value.code is EvidenceErrorCode.EVIDENCE_UNSAFE_CONTENT


@pytest.mark.parametrize("mutation", ["raw_rows", "direct_identifiers"])
def test_canonical_manifest_payload_rejects_raw_rows_and_direct_identifiers(
    mutation: str,
) -> None:
    payload = _json_example("run_manifest.example.json")
    if mutation == "raw_rows":
        payload["raw_rows"] = [["synthetic-value"]]
    else:
        privacy = cast(dict[str, object], payload["privacy"])
        privacy["direct_identifiers_sent_to_gpt"] = True
    with pytest.raises(ValidationError):
        RunManifest.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("config_type", "protocol_registry"),
        ("version", "1.0.1"),
        ("canonical_json_sha256", "0" * 64),
    ],
)
def test_registry_type_version_or_hash_drift_changes_combined_snapshot_identity(
    field: str,
    replacement: str,
) -> None:
    snapshot = load_run_registry_snapshot()
    records = [dict(record) for record in snapshot.provenance_records()]
    identity_payload = {
        "configs": [
            {
                "logical_id": record["logical_id"],
                "config_type": record["config_type"],
                "version": record["version"],
                "canonical_json_sha256": record["canonical_json_sha256"],
            }
            for record in records
        ]
    }
    assert canonical_sha256(identity_payload) == snapshot.combined_canonical_sha256
    changed_payload = copy.deepcopy(identity_payload)
    changed_records = cast(list[dict[str, object]], changed_payload["configs"])
    changed_records[0][field] = replacement
    assert canonical_sha256(changed_payload) != snapshot.combined_canonical_sha256
    assert snapshot.provenance_records()[0][field] != replacement


def test_false_config_hash_is_rejected_and_combined_hash_is_bound() -> None:
    snapshot = load_run_registry_snapshot()
    assert snapshot.combined_canonical_sha256 == (
        "3adcf2fedebc515497b24bb0eae2b51af9af4bc4bf55556a0d9e375008ed9bf2"
    )
    with pytest.raises(RegistryConfigError) as caught:
        verify_config_snapshot_hashes(
            snapshot.candidate_registry,
            expected_canonical_json_sha256="0" * 64,
        )
    assert caught.value.code is RegistryErrorCode.REGISTRY_HASH_MISMATCH
