from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from riec_guard.contract.canonicalize import (
    CANONICAL_UNIT_ALIASES,
    CONFIRMATION_FIELD_ORDER,
    ContractCanonicalizationError,
    canonicalize_audit_contract,
    compute_contract_hash,
)
from riec_guard.contract.models import (
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

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_ROOT = REPOSITORY_ROOT / "schemas" / "examples"
PROPERTY_SETTINGS = settings(
    max_examples=5,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


def _json(name: str) -> dict[str, Any]:
    value = json.loads((EXAMPLE_ROOT / name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


PROFILE = DatasetProfile.model_validate(_json("dataset_profile.example.json"))


def _ready_data() -> dict[str, Any]:
    value = _json("audit_contract.example.json")
    value["confirmation"] = {
        "status": "draft",
        "confirmed_fields": list(CONFIRMATION_FIELD_ORDER),
        "confirmed_at": None,
        "confirmed_by": "none",
    }
    return value


def _ready_contract():
    return canonicalize_audit_contract(_ready_data())


def _confirmed_contract():
    result = confirm_audit_contract(
        _ready_contract(),
        PROFILE,
        confirmed_fields=CONFIRMATION_FIELD_ORDER,
        confirmed_by=ConfirmedBy.USER,
        confirmed_at="2026-07-19T02:00:00Z",
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


ALIASES = tuple(
    (alias, canonical) for canonical, aliases in CANONICAL_UNIT_ALIASES.items() for alias in aliases
)


@PROPERTY_SETTINGS
@given(st.sampled_from(ALIASES))
def test_canonicalization_is_idempotent(alias_pair: tuple[str, str]) -> None:
    alias, _ = alias_pair
    first = canonicalize_audit_contract(_set(_ready_data(), "measurement.unit", alias))
    second = canonicalize_audit_contract(first)
    assert second == first


@PROPERTY_SETTINGS
@given(st.integers(min_value=0, max_value=10_000))
def test_canonical_json_and_hash_are_deterministic(_: int) -> None:
    contract = _ready_contract()
    assert contract.to_canonical_json() == contract.to_canonical_json()
    assert compute_contract_hash(contract) == compute_contract_hash(contract)


@PROPERTY_SETTINGS
@given(st.sampled_from(ALIASES))
def test_supported_unit_aliases_canonicalize_identically(
    alias_pair: tuple[str, str],
) -> None:
    alias, canonical = alias_pair
    first = canonicalize_audit_contract(_set(_ready_data(), "measurement.unit", alias))
    second = canonicalize_audit_contract(_set(_ready_data(), "measurement.unit", canonical))
    assert first == second


@PROPERTY_SETTINGS
@given(st.sampled_from([" ", "\t", "\n"]))
def test_permitted_whitespace_differences_canonicalize_identically(space: str) -> None:
    value = _ready_data()
    value["measurement"]["unit"] = f"{space}mL{space}"
    value["column_mapping"]["quantity"]["column"] = f"{space}quantity_ml{space}"
    value["column_mapping"]["deployment_group"]["column"] = f"{space}batch_id{space}"
    value["grouping"]["deployment_group_columns"] = [f"{space}batch_id{space}"]
    assert canonicalize_audit_contract(value) == _ready_contract()


@PROPERTY_SETTINGS
@given(st.sampled_from(["2026-07-20T01:00:00Z", "2027-01-01T00:00:00+00:00"]))
def test_created_at_does_not_change_hash(timestamp: str) -> None:
    base = _ready_contract()
    changed = canonicalize_audit_contract(_set(base.to_canonical_dict(), "created_at", timestamp))
    assert compute_contract_hash(changed) == compute_contract_hash(base)


@PROPERTY_SETTINGS
@given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-", min_size=1, max_size=20))
def test_compiler_request_id_does_not_change_hash(request_id: str) -> None:
    base = _ready_contract()
    changed = canonicalize_audit_contract(
        _set(base.to_canonical_dict(), "compiler.request_id", request_id)
    )
    assert compute_contract_hash(changed) == compute_contract_hash(base)


@PROPERTY_SETTINGS
@given(st.sampled_from(["2026-07-20T01:00:00Z", "2027-01-01T00:00:00+00:00"]))
def test_confirmation_timestamp_does_not_change_hash(timestamp: str) -> None:
    base = _confirmed_contract()
    changed = canonicalize_audit_contract(
        _set(base.to_canonical_dict(), "confirmation.confirmed_at", timestamp)
    )
    assert compute_contract_hash(changed) == compute_contract_hash(base)


@PROPERTY_SETTINGS
@given(st.floats(min_value=250.1, max_value=500, allow_nan=False, allow_infinity=False))
def test_changing_nominal_quantity_changes_hash(value: float) -> None:
    base = _ready_contract()
    changed = canonicalize_audit_contract(
        _set(base.to_canonical_dict(), "policy.nominal_quantity", value)
    )
    assert compute_contract_hash(changed) != compute_contract_hash(base)


@PROPERTY_SETTINGS
@given(st.floats(min_value=200, max_value=249.49, allow_nan=False, allow_infinity=False))
def test_changing_lower_limit_changes_hash(value: float) -> None:
    base = _ready_contract()
    changed = canonicalize_audit_contract(
        _set(base.to_canonical_dict(), "policy.lower_limit", value)
    )
    assert compute_contract_hash(changed) != compute_contract_hash(base)


@PROPERTY_SETTINGS
@given(st.floats(min_value=0.001, max_value=0.49, allow_nan=False, allow_infinity=False))
def test_changing_alpha_changes_hash(value: float) -> None:
    base = _ready_contract()
    changed = canonicalize_audit_contract(_set(base.to_canonical_dict(), "policy.alpha", value))
    if value != base.policy.alpha:
        assert compute_contract_hash(changed) != compute_contract_hash(base)


@PROPERTY_SETTINGS
@given(st.sampled_from([["shift_id"], ["batch_id", "shift_id"]]))
def test_changing_grouping_changes_hash(columns: list[str]) -> None:
    base = _ready_contract()
    changed = canonicalize_audit_contract(
        _set(base.to_canonical_dict(), "grouping.deployment_group_columns", columns)
    )
    assert compute_contract_hash(changed) != compute_contract_hash(base)


@PROPERTY_SETTINGS
@given(st.sampled_from(["public_user_upload", "private_industrial"]))
def test_changing_privacy_classification_changes_hash(classification: str) -> None:
    base = _ready_contract()
    changed = canonicalize_audit_contract(
        _set(base.to_canonical_dict(), "privacy.classification", classification)
    )
    assert compute_contract_hash(changed) != compute_contract_hash(base)


@PROPERTY_SETTINGS
@given(st.integers(min_value=0, max_value=100))
def test_draft_and_confirmed_states_have_different_hashes(_: int) -> None:
    draft = _ready_contract()
    confirmed = _confirmed_contract()
    assert compute_contract_hash(draft) != compute_contract_hash(confirmed)


@PROPERTY_SETTINGS
@given(st.integers(min_value=0, max_value=100))
def test_repeated_unchanged_confirmation_is_idempotent(_: int) -> None:
    confirmed = _confirmed_contract()
    result = confirm_audit_contract(
        confirmed,
        PROFILE,
        confirmed_fields=CONFIRMATION_FIELD_ORDER,
        confirmed_by=ConfirmedBy.USER,
        confirmed_at="2026-07-19T02:00:00Z",
    )
    assert result.idempotent and result.contract == confirmed


@PROPERTY_SETTINGS
@given(st.integers(min_value=0, max_value=100))
def test_confirmed_contract_cannot_transition_away_from_confirmed(_: int) -> None:
    confirmed = _confirmed_contract()
    result = reject_audit_contract(confirmed, PROFILE)
    assert not result.transitioned
    assert result.contract.confirmation.status is ConfirmationStatus.CONFIRMED
    assert ContractValidationCode.CONTRACT_INVALID_TRANSITION in {
        issue.code for issue in result.validation.blocking_errors
    }


@PROPERTY_SETTINGS
@given(st.booleans())
def test_random_row_fallback_can_never_become_valid(_: bool) -> None:
    value = _ready_data()
    value["grouping"]["no_random_row_fallback"] = False
    report = validate_audit_contract(value, PROFILE)
    assert not report.valid and not report.analysis_permitted


@PROPERTY_SETTINGS
@given(st.sampled_from([float("nan"), float("inf"), float("-inf")]))
def test_nonfinite_values_never_canonicalize_or_hash(value: float) -> None:
    with pytest.raises(ContractCanonicalizationError):
        canonicalize_audit_contract(_set(_ready_data(), "policy.alpha", value))


@PROPERTY_SETTINGS
@given(st.sampled_from(ALIASES))
def test_contract_ids_always_match_first_twelve_uppercase_hex(
    alias_pair: tuple[str, str],
) -> None:
    contract = canonicalize_audit_contract(_set(_ready_data(), "measurement.unit", alias_pair[0]))
    identity = compute_contract_hash(contract)
    assert identity.contract_id == f"AC-{identity.canonical_contract_sha256[:12].upper()}"
    assert contract.contract_id == identity.contract_id


@PROPERTY_SETTINGS
@given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=12))
def test_blocking_unresolved_fields_always_prevent_analysis(question: str) -> None:
    value = _ready_data()
    value["unresolved_fields"] = [
        {"field_path": "policy.alpha", "severity": "blocking", "question": question}
    ]
    report = validate_audit_contract(canonicalize_audit_contract(value), PROFILE)
    assert not report.analysis_permitted


@PROPERTY_SETTINGS
@given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=12))
def test_unconfirmed_gpt_assumptions_always_prevent_confirmation(text: str) -> None:
    value = _ready_data()
    value["assumptions"] = [
        {
            "assumption_id": "ASM-001",
            "text": text,
            "source": "gpt_inference",
            "user_confirmed": False,
        }
    ]
    contract = canonicalize_audit_contract(value)
    result = confirm_audit_contract(
        contract,
        PROFILE,
        confirmed_fields=CONFIRMATION_FIELD_ORDER,
        confirmed_by=ConfirmedBy.USER,
        confirmed_at="2026-07-19T02:00:00Z",
    )
    assert not result.transitioned


@PROPERTY_SETTINGS
@given(st.booleans())
def test_tie_break_order_is_preserved_and_affects_hash(reverse: bool) -> None:
    first_order = ["row_sequence", "stream_id"]
    second_order = list(reversed(first_order)) if reverse else first_order
    first = canonicalize_audit_contract(
        _set(_ready_data(), "ordering.tie_break_columns", first_order)
    )
    second = canonicalize_audit_contract(
        _set(_ready_data(), "ordering.tie_break_columns", second_order)
    )
    assert second.ordering.tie_break_columns == tuple(second_order)
    assert (compute_contract_hash(first) != compute_contract_hash(second)) is reverse


@PROPERTY_SETTINGS
@given(st.permutations(CONFIRMATION_FIELD_ORDER))
def test_confirmed_field_input_order_does_not_affect_hash(fields: list[str]) -> None:
    first = canonicalize_audit_contract(_ready_data())
    value = _ready_data()
    value["confirmation"]["confirmed_fields"] = fields
    second = canonicalize_audit_contract(value)
    assert first == second


@PROPERTY_SETTINGS
@given(
    st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_", min_size=3, max_size=12).filter(
        lambda value: value not in {column.name for column in PROFILE.column_profiles}
    )
)
def test_canonicalization_never_creates_a_profile_column(column: str) -> None:
    contract = canonicalize_audit_contract(
        _set(_ready_data(), "column_mapping.quantity.column", f" {column} ")
    )
    assert contract.column_mapping.quantity.column == column
    report = validate_audit_contract(contract, PROFILE)
    assert ContractValidationCode.CONTRACT_COLUMN_NOT_FOUND in {
        issue.code for issue in report.blocking_errors
    }


@PROPERTY_SETTINGS
@given(st.sampled_from(["draft", "confirmed", "rejected"]))
def test_analysis_permission_implies_validation_and_complete_confirmation(status: str) -> None:
    if status == "confirmed":
        contract = _confirmed_contract()
    elif status == "rejected":
        contract = reject_audit_contract(_ready_contract(), PROFILE).contract
    else:
        contract = _ready_contract()
    report = validate_audit_contract(contract, PROFILE)
    if report.analysis_permitted:
        assert report.valid
        assert report.confirmation_required == ()
        assert contract.confirmation.status is ConfirmationStatus.CONFIRMED
        assert report.contract_id == contract.contract_id
