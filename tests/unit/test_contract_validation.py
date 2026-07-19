from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any, cast

import pytest

from riec_guard.contract.canonicalize import (
    CANONICAL_UNIT_ALIASES,
    CONFIRMATION_FIELD_ORDER,
    ContractCanonicalizationError,
    canonicalize_audit_contract,
    compute_contract_hash,
    normalize_unit,
)
from riec_guard.contract.models import (
    AuditContract,
    ConfirmedBy,
    ConfirmationStatus,
    ContractRuntimeContext,
    ContractValidationCode,
    DatasetProfile,
)
from riec_guard.contract.validator import (
    DECISION_CRITICAL_CONFIRMATION_FIELDS,
    analysis_is_permitted,
    confirm_audit_contract,
    reject_audit_contract,
    validate_audit_contract,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_ROOT = REPOSITORY_ROOT / "schemas" / "examples"


def _json(name: str) -> dict[str, Any]:
    value = json.loads((EXAMPLE_ROOT / name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _profile() -> DatasetProfile:
    return DatasetProfile.model_validate(_json("dataset_profile.example.json"))


def _frozen_contract() -> AuditContract:
    return AuditContract.model_validate(_json("audit_contract.example.json"))


def _ready_draft_data() -> dict[str, Any]:
    value = _json("audit_contract.example.json")
    value["confirmation"] = {
        "status": "draft",
        "confirmed_fields": list(CONFIRMATION_FIELD_ORDER),
        "confirmed_at": None,
        "confirmed_by": "none",
    }
    return value


def _ready_draft() -> AuditContract:
    return canonicalize_audit_contract(_ready_draft_data())


def _confirmed(
    contract: AuditContract | None = None,
    profile: DatasetProfile | None = None,
    *,
    runtime_context: ContractRuntimeContext = ContractRuntimeContext.HOSTED_PUBLIC,
) -> AuditContract:
    result = confirm_audit_contract(
        contract or _ready_draft(),
        profile or _profile(),
        confirmed_fields=CONFIRMATION_FIELD_ORDER,
        confirmed_by=ConfirmedBy.USER,
        confirmed_at="2026-07-19T02:00:00Z",
        runtime_context=runtime_context,
    )
    assert result.transitioned
    return result.contract


def _set(value: dict[str, Any], path: str, replacement: object) -> dict[str, Any]:
    result = copy.deepcopy(value)
    current: dict[str, Any] = result
    parts = path.split(".")
    for part in parts[:-1]:
        child = current[part]
        assert isinstance(child, dict)
        current = child
    current[parts[-1]] = replacement
    return result


def _contract_data(contract: AuditContract | None = None) -> dict[str, Any]:
    return (contract or _ready_draft()).to_canonical_dict()


def _profile_with(**updates: tuple[str, object]) -> DatasetProfile:
    value = _profile().to_canonical_dict()
    columns = value["column_profiles"]
    assert isinstance(columns, list)
    for name, (field, replacement) in updates.items():
        column = next(item for item in columns if isinstance(item, dict) and item["name"] == name)
        column[field] = replacement
    return DatasetProfile.model_validate(value)


def _codes(report: object) -> set[ContractValidationCode]:
    blocking = getattr(report, "blocking_errors")
    return {issue.code for issue in blocking}


def test_frozen_canonical_audit_contract_example_is_losslessly_typed() -> None:
    source = _json("audit_contract.example.json")
    contract = AuditContract.model_validate(source)
    assert contract.to_canonical_dict() == source


def test_frozen_example_hash_reproduces_contract_id_exactly() -> None:
    contract = _frozen_contract()
    identity = compute_contract_hash(contract)
    assert identity.canonical_contract_sha256 == (
        "84e73f9b8fb08527de0e976958b1aa83b2bf78f25990ceb6fe86930c7479b6dd"
    )
    assert identity.contract_id == contract.contract_id == "AC-84E73F9B8FB0"


def test_frozen_example_remains_schema_valid_but_exposes_new_exact_confirmation_gaps() -> None:
    report = validate_audit_contract(_frozen_contract(), _profile())
    assert report.confirmation_required == (
        "measurement.quantity_semantics",
        "ordering.time_column",
    )
    assert ContractValidationCode.CONTRACT_CONFIRMATION_INCOMPLETE in _codes(report)
    assert not report.analysis_permitted


def test_ready_draft_is_valid_but_not_analysis_permitted() -> None:
    report = validate_audit_contract(_ready_draft(), _profile())
    assert report.valid
    assert not report.analysis_permitted
    assert not analysis_is_permitted(report)
    assert report.confirmation_required == ()


def test_valid_explicit_confirmation_produces_new_confirmed_identity() -> None:
    draft = _ready_draft()
    result = confirm_audit_contract(
        draft,
        _profile(),
        confirmed_fields=tuple(reversed(CONFIRMATION_FIELD_ORDER)),
        confirmed_by=ConfirmedBy.USER,
        confirmed_at="2026-07-19T02:00:00Z",
    )
    assert result.transitioned and not result.idempotent
    assert result.contract.confirmation.status is ConfirmationStatus.CONFIRMED
    assert result.contract.contract_id != draft.contract_id
    assert result.validation.valid


def test_confirmed_contract_is_analysis_permitted_and_g1_eligible() -> None:
    contract = _confirmed()
    report = validate_audit_contract(contract, _profile())
    assert report.valid
    assert report.analysis_permitted
    assert report.g1_eligible
    assert report.contract_id == contract.contract_id


def test_rejected_contract_is_never_analysis_permitted() -> None:
    result = reject_audit_contract(_ready_draft(), _profile())
    assert result.transitioned
    assert result.contract.confirmation.status is ConfirmationStatus.REJECTED
    assert not result.validation.analysis_permitted


def test_missing_decision_confirmation_field_blocks_transition() -> None:
    fields = tuple(field for field in CONFIRMATION_FIELD_ORDER if field != "policy.alpha")
    result = confirm_audit_contract(
        _ready_draft(),
        _profile(),
        confirmed_fields=fields,
        confirmed_by=ConfirmedBy.USER,
        confirmed_at="2026-07-19T02:00:00Z",
    )
    assert not result.transitioned
    assert ContractValidationCode.CONTRACT_CONFIRMATION_INCOMPLETE in _codes(result.validation)


@pytest.mark.parametrize(
    ("path", "code"),
    [
        ("column_mapping.quantity.confirmed", ContractValidationCode.CONTRACT_QUANTITY_UNCONFIRMED),
        (
            "column_mapping.deployment_group.confirmed",
            ContractValidationCode.CONTRACT_GROUP_UNCONFIRMED,
        ),
    ],
)
def test_unconfirmed_required_column_mappings_block(
    path: str, code: ContractValidationCode
) -> None:
    contract = canonicalize_audit_contract(_set(_ready_draft_data(), path, False))
    assert code in _codes(validate_audit_contract(contract, _profile()))


def test_blocking_unresolved_field_blocks_without_deletion() -> None:
    value = _ready_draft_data()
    value["unresolved_fields"] = [
        {"field_path": "policy.alpha", "severity": "blocking", "question": "Confirm alpha."}
    ]
    contract = canonicalize_audit_contract(value)
    report = validate_audit_contract(contract, _profile())
    assert ContractValidationCode.CONTRACT_UNRESOLVED_BLOCKING in _codes(report)
    assert len(contract.unresolved_fields) == 1


def test_warning_unresolved_field_remains_visible_without_blocking() -> None:
    value = _ready_draft_data()
    value["unresolved_fields"] = [
        {"field_path": "policy.notes", "severity": "warning", "question": "Review note."}
    ]
    report = validate_audit_contract(canonicalize_audit_contract(value), _profile())
    assert report.valid
    assert [issue.code for issue in report.warnings] == [
        ContractValidationCode.CONTRACT_UNRESOLVED_WARNING
    ]


def test_unconfirmed_gpt_assumption_blocks_confirmation() -> None:
    value = _ready_draft_data()
    value["assumptions"] = [
        {
            "assumption_id": "ASM-001",
            "text": "Unconfirmed inference",
            "source": "gpt_inference",
            "user_confirmed": False,
        }
    ]
    report = validate_audit_contract(canonicalize_audit_contract(value), _profile())
    assert ContractValidationCode.CONTRACT_ASSUMPTION_UNCONFIRMED in _codes(report)


def test_confirmed_user_assumption_passes() -> None:
    value = _ready_draft_data()
    value["assumptions"] = [
        {
            "assumption_id": "ASM-001",
            "text": "Explicit user assumption",
            "source": "user",
            "user_confirmed": True,
        }
    ]
    assert validate_audit_contract(canonicalize_audit_contract(value), _profile()).valid


def test_unknown_unit_is_preserved_and_blocks() -> None:
    contract = canonicalize_audit_contract(_set(_ready_draft_data(), "measurement.unit", "oz"))
    assert contract.measurement.unit == "oz"
    assert ContractValidationCode.CONTRACT_UNIT_UNKNOWN in _codes(
        validate_audit_contract(contract, _profile())
    )


@pytest.mark.parametrize(
    ("alias", "canonical"),
    [
        ("ml", "mL"),
        ("millilitres", "mL"),
        ("liter", "L"),
        ("µL", "uL"),
        ("microliters", "uL"),
        ("grams", "g"),
        ("kilogram", "kg"),
        ("milligrams", "mg"),
    ],
)
def test_unit_aliases_normalize_without_numeric_conversion(alias: str, canonical: str) -> None:
    value = _set(_ready_draft_data(), "measurement.unit", f" {alias} ")
    contract = canonicalize_audit_contract(value)
    assert contract.measurement.unit == canonical
    assert contract.policy.nominal_quantity == 250.0


def test_unit_registry_has_exact_canonical_units() -> None:
    assert tuple(CANONICAL_UNIT_ALIASES) == ("mL", "L", "uL", "g", "kg", "mg")
    assert normalize_unit("unknown") is None


def test_quantity_semantics_unit_mismatch_blocks() -> None:
    value = _set(_ready_draft_data(), "measurement.quantity_semantics", "mass")
    report = validate_audit_contract(canonicalize_audit_contract(value), _profile())
    assert ContractValidationCode.CONTRACT_UNIT_SEMANTICS_MISMATCH in _codes(report)


def test_lower_limit_above_nominal_blocks() -> None:
    value = _set(_ready_draft_data(), "policy.lower_limit", 251.0)
    assert ContractValidationCode.CONTRACT_POLICY_ORDER_INVALID in _codes(
        validate_audit_contract(canonicalize_audit_contract(value), _profile())
    )


@pytest.mark.parametrize("alpha", [0, 0.5])
def test_alpha_boundaries_have_specific_reason(alpha: float) -> None:
    report = validate_audit_contract(_set(_ready_draft_data(), "policy.alpha", alpha), _profile())
    assert ContractValidationCode.CONTRACT_ALPHA_INVALID in _codes(report)


def test_screening_shift_below_action_shift_blocks() -> None:
    value = _set(_ready_draft_data(), "policy.maximum_screening_shift", 0.05)
    report = validate_audit_contract(canonicalize_audit_contract(value), _profile())
    assert ContractValidationCode.CONTRACT_SHIFT_RANGE_INVALID in _codes(report)


@pytest.mark.parametrize("resolution", [0, -0.1])
def test_invalid_measurement_resolution_has_specific_reason(resolution: float) -> None:
    report = validate_audit_contract(
        _set(_ready_draft_data(), "measurement.measurement_resolution", resolution), _profile()
    )
    assert ContractValidationCode.CONTRACT_RESOLUTION_INVALID in _codes(report)


def test_invalid_fixed_density_has_specific_reason() -> None:
    value = _ready_draft_data()
    value["measurement"]["conversion"] = {
        "required": True,
        "method": "fixed_density",
        "fixed_density": -1,
        "formula_note": None,
    }
    assert ContractValidationCode.CONTRACT_CONVERSION_INVALID in _codes(
        validate_audit_contract(value, _profile())
    )


@pytest.mark.parametrize("method", ["row_density", "gross_minus_tare"])
def test_conversion_without_required_profile_mappings_blocks(method: str) -> None:
    value = _ready_draft_data()
    value["measurement"]["conversion"] = {
        "required": True,
        "method": method,
        "fixed_density": None,
        "formula_note": None,
    }
    report = validate_audit_contract(canonicalize_audit_contract(value), _profile())
    assert ContractValidationCode.CONTRACT_CONVERSION_INVALID in _codes(report)


def test_required_conversion_cannot_use_none() -> None:
    value = _ready_draft_data()
    value["measurement"]["conversion"]["required"] = True
    report = validate_audit_contract(canonicalize_audit_contract(value), _profile())
    assert ContractValidationCode.CONTRACT_CONVERSION_INVALID in _codes(report)


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        ("source.dataset_sha256", "f" * 64),
        ("source.row_count", 599),
        ("source.column_count", 8),
    ],
)
def test_source_profile_identity_and_count_mismatches_block(path: str, replacement: object) -> None:
    contract = canonicalize_audit_contract(_set(_ready_draft_data(), path, replacement))
    assert ContractValidationCode.CONTRACT_SOURCE_PROFILE_MISMATCH in _codes(
        validate_audit_contract(contract, _profile())
    )


def test_unknown_column_is_not_casefold_remapped() -> None:
    value = _set(_ready_draft_data(), "column_mapping.quantity.column", "Quantity_ML")
    contract = canonicalize_audit_contract(value)
    assert contract.column_mapping.quantity.column == "Quantity_ML"
    assert ContractValidationCode.CONTRACT_COLUMN_NOT_FOUND in _codes(
        validate_audit_contract(contract, _profile())
    )


def test_nonnumeric_quantity_column_blocks() -> None:
    value = _set(_ready_draft_data(), "column_mapping.quantity.column", "product_id")
    report = validate_audit_contract(canonicalize_audit_contract(value), _profile())
    assert ContractValidationCode.CONTRACT_QUANTITY_NOT_NUMERIC in _codes(report)


def test_constant_deployment_group_blocks() -> None:
    profile = _profile_with(batch_id=("unique_count", 1))
    assert ContractValidationCode.CONTRACT_GROUP_CONSTANT in _codes(
        validate_audit_contract(_ready_draft(), profile)
    )


def test_missing_deployment_group_values_block() -> None:
    profile = _profile_with(batch_id=("missing_fraction", 0.1))
    assert ContractValidationCode.CONTRACT_GROUP_MISSING_VALUES in _codes(
        validate_audit_contract(_ready_draft(), profile)
    )


def test_too_few_groups_for_exploratory_use_blocks() -> None:
    profile = _profile_with(batch_id=("unique_count", 3))
    assert ContractValidationCode.CONTRACT_INSUFFICIENT_GROUPS in _codes(
        validate_audit_contract(_ready_draft(), profile)
    )


def test_exploratory_only_group_support_is_a_warning() -> None:
    report = validate_audit_contract(_ready_draft(), _profile_with(batch_id=("unique_count", 6)))
    assert report.valid
    assert ContractValidationCode.CONTRACT_INSUFFICIENT_GROUPS in {
        issue.code for issue in report.warnings
    }


def test_composite_grouping_remains_explicit_and_not_analysis_permitted() -> None:
    value = _ready_draft_data()
    value["grouping"]["deployment_group_columns"] = ["batch_id", "shift_id"]
    contract = canonicalize_audit_contract(value)
    report = validate_audit_contract(contract, _profile())
    assert contract.grouping.deployment_group_columns == ("batch_id", "shift_id")
    assert report.valid and not report.analysis_permitted
    assert ContractValidationCode.CONTRACT_INSUFFICIENT_GROUPS in {
        issue.code for issue in report.warnings
    }


def test_confirmed_ordering_without_time_column_blocks() -> None:
    value = _set(_ready_draft_data(), "ordering.time_column", None)
    assert ContractValidationCode.CONTRACT_ORDERING_INCONSISTENT in _codes(
        validate_audit_contract(value, _profile())
    )


def test_confirmed_ordering_with_nondatetime_column_blocks() -> None:
    value = _ready_draft_data()
    value["ordering"]["time_column"] = "product_id"
    value["column_mapping"]["time"]["column"] = "product_id"
    report = validate_audit_contract(canonicalize_audit_contract(value), _profile())
    assert ContractValidationCode.CONTRACT_ORDERING_INCONSISTENT in _codes(report)


def test_ordering_and_time_mapping_mismatch_blocks() -> None:
    value = _set(_ready_draft_data(), "column_mapping.time.column", "row_sequence")
    report = validate_audit_contract(canonicalize_audit_contract(value), _profile())
    assert ContractValidationCode.CONTRACT_ORDERING_INCONSISTENT in _codes(report)


@pytest.mark.parametrize("status", ["unavailable", "ambiguous"])
def test_nonconfirmed_ordering_preserves_status_and_g1_ineligibility(status: str) -> None:
    value = _ready_draft_data()
    value["ordering"]["status"] = status
    value["ordering"]["time_column"] = None if status == "unavailable" else "timestamp"
    value["ordering"]["within_stream_order_confirmed"] = False
    draft = canonicalize_audit_contract(value)
    confirmed = _confirmed(draft)
    report = validate_audit_contract(confirmed, _profile())
    assert report.valid and report.analysis_permitted and not report.g1_eligible
    assert confirmed.ordering.status.value == status
    assert ContractValidationCode.CONTRACT_ORDER_UNCONFIRMED in {
        issue.code for issue in report.warnings
    }


def test_g1_requires_confirmed_stream_mapping() -> None:
    value = _set(_ready_draft_data(), "column_mapping.stream.confirmed", False)
    draft = canonicalize_audit_contract(value)
    confirmed = _confirmed(draft)
    report = validate_audit_contract(confirmed, _profile())
    assert report.analysis_permitted and not report.g1_eligible


def test_hosted_runtime_rejects_private_mode() -> None:
    value = _ready_draft_data()
    value["source"]["mode"] = "local_private"
    value["privacy"]["classification"] = "private_industrial"
    value["privacy"]["storage_mode"] = "local_private_workspace"
    report = validate_audit_contract(canonicalize_audit_contract(value), _profile())
    assert ContractValidationCode.CONTRACT_PRIVACY_MODE_INVALID in _codes(report)


def test_local_private_runtime_accepts_consistent_private_mode() -> None:
    value = _ready_draft_data()
    value["source"]["mode"] = "local_private"
    value["privacy"]["classification"] = "private_industrial"
    value["privacy"]["storage_mode"] = "local_private_workspace"
    draft = canonicalize_audit_contract(value)
    report = validate_audit_contract(
        draft, _profile(), runtime_context=ContractRuntimeContext.LOCAL_PRIVATE
    )
    assert report.valid


@pytest.mark.parametrize("field", ["raw_rows_to_gpt", "direct_identifiers_to_gpt"])
def test_gpt_data_flags_can_never_validate_true(field: str) -> None:
    value = _set(_ready_draft_data(), f"privacy.{field}", True)
    assert ContractValidationCode.CONTRACT_PRIVACY_MODE_INVALID in _codes(
        validate_audit_contract(value, _profile())
    )


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        ("riec.baseline_candidate_id", "M1_bad"),
        ("riec.risk_aggregation", "group_balanced_mse"),
        ("riec.splitter", "random_rows"),
        ("riec.c", -1),
        ("riec.near_tie_abs_tol", -1),
        ("riec.near_tie_rel_tol", -1),
    ],
)
def test_invalid_riec_settings_have_stable_reason(path: str, replacement: object) -> None:
    report = validate_audit_contract(_set(_ready_draft_data(), path, replacement), _profile())
    assert ContractValidationCode.CONTRACT_RIEC_SETTINGS_INVALID in _codes(report)


def test_incoming_incorrect_contract_id_is_recomputed_by_canonicalizer() -> None:
    value = _ready_draft_data()
    value["contract_id"] = "AC-FFFFFFFFFFFF"
    canonical = canonicalize_audit_contract(value)
    assert canonical.contract_id != "AC-FFFFFFFFFFFF"
    assert canonical.contract_id == compute_contract_hash(canonical).contract_id


def test_incoming_confirmed_identity_mismatch_is_blocking() -> None:
    value = _confirmed().to_canonical_dict()
    value["contract_id"] = "AC-FFFFFFFFFFFF"
    report = validate_audit_contract(value, _profile())
    assert ContractValidationCode.CONTRACT_CONFIRMATION_INCOMPLETE in _codes(report)
    assert not report.analysis_permitted
    assert report.contract_id != value["contract_id"]


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        ("created_at", "2026-07-20T01:00:00Z"),
        ("compiler.request_id", "request-two"),
        ("confirmation.confirmed_at", "2026-07-20T02:00:00Z"),
    ],
)
def test_excluded_runtime_fields_do_not_change_hash(path: str, replacement: object) -> None:
    source = _frozen_contract()
    changed = canonicalize_audit_contract(_set(source.to_canonical_dict(), path, replacement))
    assert compute_contract_hash(changed) == compute_contract_hash(source)


def test_decision_critical_change_creates_new_draft_identity() -> None:
    confirmed = _confirmed()
    value = confirmed.to_canonical_dict()
    policy = cast(dict[str, Any], value["policy"])
    confirmation = cast(dict[str, Any], value["confirmation"])
    policy["alpha"] = 0.02
    confirmation["status"] = "draft"
    confirmation["confirmed_at"] = None
    confirmation["confirmed_by"] = "none"
    draft = canonicalize_audit_contract(value)
    report = validate_audit_contract(draft, _profile())
    assert draft.contract_id != confirmed.contract_id
    assert not report.analysis_permitted


def test_repeated_identical_confirmation_is_explicitly_idempotent() -> None:
    confirmed = _confirmed()
    result = confirm_audit_contract(
        confirmed,
        _profile(),
        confirmed_fields=CONFIRMATION_FIELD_ORDER,
        confirmed_by=ConfirmedBy.USER,
        confirmed_at="2026-07-19T02:00:00Z",
    )
    assert result.idempotent and not result.transitioned
    assert result.contract == confirmed


def test_changed_confirmed_content_with_stale_identity_is_not_idempotent() -> None:
    confirmed = _confirmed()
    value = confirmed.to_canonical_dict()
    policy = cast(dict[str, Any], value["policy"])
    policy["alpha"] = 0.02
    changed_with_stale_identity = AuditContract.model_validate(value)
    result = confirm_audit_contract(
        changed_with_stale_identity,
        _profile(),
        confirmed_fields=CONFIRMATION_FIELD_ORDER,
        confirmed_by=ConfirmedBy.USER,
        confirmed_at="2026-07-19T02:00:00Z",
    )
    assert not result.transitioned
    assert not result.idempotent
    assert ContractValidationCode.CONTRACT_INVALID_TRANSITION in _codes(result.validation)


def test_confirmed_contract_cannot_transition_to_rejected() -> None:
    confirmed = _confirmed()
    result = reject_audit_contract(confirmed, _profile())
    assert not result.transitioned
    assert result.contract.confirmation.status is ConfirmationStatus.CONFIRMED
    assert ContractValidationCode.CONTRACT_INVALID_TRANSITION in _codes(result.validation)


def test_setting_status_alone_never_permits_analysis() -> None:
    value = _ready_draft_data()
    value["confirmation"]["status"] = "confirmed"
    value["confirmation"]["confirmed_at"] = "2026-07-19T02:00:00Z"
    value["confirmation"]["confirmed_by"] = "user"
    value["confirmation"]["confirmed_fields"] = []
    contract = canonicalize_audit_contract(value)
    report = validate_audit_contract(contract, _profile())
    assert not report.analysis_permitted
    assert ContractValidationCode.CONTRACT_CONFIRMATION_INCOMPLETE in _codes(report)


def test_policy_source_must_be_confirmed() -> None:
    value = _set(_ready_draft_data(), "policy.policy_source.user_confirmed", False)
    report = validate_audit_contract(canonicalize_audit_contract(value), _profile())
    assert ContractValidationCode.CONTRACT_CONFIRMATION_INCOMPLETE in _codes(report)


def test_versioned_builtin_service_may_confirm_its_builtin_policy_path() -> None:
    value = _set(_ready_draft_data(), "policy.policy_source.user_confirmed", False)
    draft = canonicalize_audit_contract(value)
    result = confirm_audit_contract(
        draft,
        _profile(),
        confirmed_fields=CONFIRMATION_FIELD_ORDER,
        confirmed_by=ConfirmedBy.VERSIONED_BUILTIN,
        confirmed_at="2026-07-19T02:00:00Z",
    )
    assert result.transitioned
    assert result.validation.analysis_permitted


def test_user_cannot_substitute_for_unconfirmed_builtin_policy_source() -> None:
    value = _set(_ready_draft_data(), "policy.policy_source.user_confirmed", False)
    draft = canonicalize_audit_contract(value)
    result = confirm_audit_contract(
        draft,
        _profile(),
        confirmed_fields=CONFIRMATION_FIELD_ORDER,
        confirmed_by=ConfirmedBy.USER,
        confirmed_at="2026-07-19T02:00:00Z",
    )
    assert not result.transitioned
    assert ContractValidationCode.CONTRACT_CONFIRMATION_INCOMPLETE in _codes(result.validation)


def test_confirmation_fields_are_deduplicated_in_fixed_semantic_order() -> None:
    value = _ready_draft_data()
    value["confirmation"]["confirmed_fields"] = [
        "privacy.classification",
        "policy.alpha",
        "privacy.classification",
        "column_mapping.quantity.column",
    ]
    contract = canonicalize_audit_contract(value)
    assert contract.confirmation.confirmed_fields == (
        "column_mapping.quantity.column",
        "policy.alpha",
        "privacy.classification",
    )


def test_tie_break_and_composite_group_order_are_preserved() -> None:
    value = _ready_draft_data()
    value["ordering"]["tie_break_columns"] = ["stream_id", "row_sequence"]
    value["grouping"]["deployment_group_columns"] = ["batch_id", "shift_id"]
    contract = canonicalize_audit_contract(value)
    assert contract.ordering.tie_break_columns == ("stream_id", "row_sequence")
    assert contract.grouping.deployment_group_columns == ("batch_id", "shift_id")


def test_unresolved_and_assumptions_have_deterministic_nonlossy_order() -> None:
    value = _ready_draft_data()
    value["unresolved_fields"] = [
        {"field_path": "z", "severity": "warning", "question": "Z?"},
        {"field_path": "a", "severity": "blocking", "question": "A?"},
    ]
    value["assumptions"] = [
        {"assumption_id": "ASM-002", "text": "B", "source": "user", "user_confirmed": True},
        {"assumption_id": "ASM-001", "text": "A", "source": "user", "user_confirmed": True},
    ]
    contract = canonicalize_audit_contract(value)
    assert [item.field_path for item in contract.unresolved_fields] == ["a", "z"]
    assert [item.assumption_id for item in contract.assumptions] == ["ASM-001", "ASM-002"]


def test_duplicate_assumption_ids_fail_without_silent_deduplication() -> None:
    value = _ready_draft_data()
    value["assumptions"] = [
        {"assumption_id": "ASM-001", "text": "A", "source": "user", "user_confirmed": True},
        {"assumption_id": "ASM-001", "text": "B", "source": "user", "user_confirmed": True},
    ]
    with pytest.raises(ContractCanonicalizationError):
        canonicalize_audit_contract(value)


def test_validation_issues_do_not_echo_unknown_column_values_or_paths() -> None:
    sensitive = "SENSITIVE_UNKNOWN_COLUMN_VALUE"
    value = _set(_ready_draft_data(), "column_mapping.quantity.column", sensitive)
    report = validate_audit_contract(canonicalize_audit_contract(value), _profile())
    serialized = report.model_dump_json()
    assert sensitive not in serialized
    assert "Traceback" not in serialized
    assert not re.search(r"(?:/[A-Za-z0-9._ -]+){2,}", serialized)


def test_issue_ordering_is_deterministic() -> None:
    value = _ready_draft_data()
    value["column_mapping"]["quantity"]["confirmed"] = False
    value["column_mapping"]["deployment_group"]["confirmed"] = False
    first = validate_audit_contract(canonicalize_audit_contract(value), _profile())
    second = validate_audit_contract(canonicalize_audit_contract(value), _profile())
    assert first == second
    keys = [(issue.code.value, issue.field_path) for issue in first.blocking_errors]
    assert keys == sorted(keys)


def test_canonical_result_validates_against_frozen_audit_contract_schema() -> None:
    contract = canonicalize_audit_contract(_ready_draft_data())
    assert AuditContract.model_validate(contract.to_canonical_dict()) == contract


def test_decision_critical_field_list_is_exact_and_time_is_conditional() -> None:
    assert DECISION_CRITICAL_CONFIRMATION_FIELDS == tuple(
        field for field in CONFIRMATION_FIELD_ORDER if field != "ordering.time_column"
    )
