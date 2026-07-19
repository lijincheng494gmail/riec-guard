from __future__ import annotations

import copy
import json
import math
from collections.abc import Callable
from typing import cast

import pytest
from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from pydantic import ValidationError

from riec_guard.contract.models import (
    CANONICAL_MODEL_REGISTRY,
    ActionDecision,
    AuditContract,
    CanonicalModelRegistryError,
    ClaimAudit,
    DatasetProfile,
    ProtocolResult,
    RiecSelection,
    get_canonical_model,
)
from riec_guard.contract.schema_loader import SchemaKind, load_schema_registry
from riec_guard.errors import (
    ApplicationError,
    ErrorCode,
    ErrorEnvelope,
    ErrorStage,
    error_envelope_from_exception,
)
from riec_guard.evidence.models import EvidenceLedger
from riec_guard.telemetry.models import RunManifest

EXPECTED_CANONICAL_NAMES = {
    "action_decision",
    "audit_contract",
    "candidate_registry",
    "claim_audit",
    "dataset_profile",
    "error_envelope",
    "evidence_ledger",
    "protocol_result",
    "report_draft",
    "riec_selection",
    "run_manifest",
}


def _example(logical_name: str) -> dict[str, object]:
    return load_schema_registry().lookup(logical_name).example()


def _mutated(logical_name: str, mutate: Callable[[dict[str, object]], None]) -> dict[str, object]:
    value = copy.deepcopy(_example(logical_name))
    mutate(value)
    return value


def _assert_invalid(
    logical_name: str, mutate: Callable[[dict[str, object]], None]
) -> ValidationError:
    with pytest.raises(ValidationError) as exc_info:
        get_canonical_model(logical_name).model_validate(_mutated(logical_name, mutate))
    return exc_info.value


def test_model_registry_contains_exactly_the_11_canonical_names() -> None:
    assert len(CANONICAL_MODEL_REGISTRY) == 11
    assert set(CANONICAL_MODEL_REGISTRY) == EXPECTED_CANONICAL_NAMES


def test_model_registry_has_no_gpt_projection_names() -> None:
    projection_names = {record.logical_name for record in load_schema_registry().gpt_projections()}
    assert set(CANONICAL_MODEL_REGISTRY).isdisjoint(projection_names)


def test_model_registry_is_read_only_and_unknown_names_are_rejected() -> None:
    with pytest.raises(TypeError):
        CANONICAL_MODEL_REGISTRY["unknown"] = AuditContract  # type: ignore[index]
    with pytest.raises(CanonicalModelRegistryError) as exc_info:
        get_canonical_model("unknown")
    assert exc_info.value.code == "CANONICAL_MODEL_NOT_REGISTERED"


@pytest.mark.parametrize("logical_name", sorted(EXPECTED_CANONICAL_NAMES))
def test_every_canonical_example_validates_through_its_typed_model(logical_name: str) -> None:
    model = get_canonical_model(logical_name).model_validate(_example(logical_name))
    assert model.schema_logical_name == logical_name


@pytest.mark.parametrize("logical_name", sorted(EXPECTED_CANONICAL_NAMES))
def test_every_model_dump_validates_against_its_canonical_schema(logical_name: str) -> None:
    registry = load_schema_registry()
    record = registry.lookup(logical_name)
    model = get_canonical_model(logical_name).model_validate(record.example())
    Draft202012Validator(record.validation_schema(), format_checker=FormatChecker()).validate(
        model.to_canonical_dict()
    )


@pytest.mark.parametrize("logical_name", sorted(EXPECTED_CANONICAL_NAMES))
def test_every_frozen_example_round_trips_without_information_loss(logical_name: str) -> None:
    original = _example(logical_name)
    model = get_canonical_model(logical_name).model_validate(original)
    assert model.to_canonical_dict() == original


def test_explicit_null_fields_remain_explicit_null() -> None:
    original = _example("audit_contract")
    model = AuditContract.model_validate(original)
    result = model.to_canonical_dict()
    assert "created_at" in result
    assert result["compiler"]["model"] is None  # type: ignore[index]
    assert result["measurement"]["conversion"]["fixed_density"] is None  # type: ignore[index]


def test_omitted_optional_fields_remain_omitted() -> None:
    def omit(value: dict[str, object]) -> None:
        value.pop("created_at")
        value.pop("compiler")

    value = _mutated("audit_contract", omit)
    result = AuditContract.model_validate(value).to_canonical_dict()
    assert "created_at" not in result
    assert "compiler" not in result


def test_empty_arrays_and_objects_present_in_input_are_preserved() -> None:
    contract = AuditContract.model_validate(
        _mutated("audit_contract", lambda item: item.update(assumptions=[]))
    )
    envelope = ErrorEnvelope.model_validate(
        _mutated("error_envelope", lambda item: item.update(safe_details={}, cause_chain=[]))
    )
    assert contract.to_canonical_dict()["assumptions"] == []
    assert envelope.to_canonical_dict()["safe_details"] == {}
    assert envelope.to_canonical_dict()["cause_chain"] == []


def test_invalid_root_enum_fails() -> None:
    _assert_invalid("action_decision", lambda value: value.update(state="stronger_state"))


def test_invalid_nested_enum_fails() -> None:
    def mutate(value: dict[str, object]) -> None:
        value["gates"]["ordered_stability"] = "certified"  # type: ignore[index]

    _assert_invalid("action_decision", mutate)


def test_unknown_root_field_fails_when_forbidden() -> None:
    _assert_invalid("riec_selection", lambda value: value.update(hidden_score=1.0))


def test_unknown_nested_critical_field_fails_when_forbidden() -> None:
    def mutate(value: dict[str, object]) -> None:
        value["policy"]["unstated_threshold"] = 0  # type: ignore[index]

    _assert_invalid("audit_contract", mutate)


def test_numeric_string_is_not_coerced_to_number() -> None:
    def mutate(value: dict[str, object]) -> None:
        value["riec"]["c"] = "1.0"  # type: ignore[index]

    _assert_invalid("audit_contract", mutate)


def test_integer_is_not_coerced_to_boolean() -> None:
    def mutate(value: dict[str, object]) -> None:
        value["gates"]["contract_valid"] = 1  # type: ignore[index]

    _assert_invalid("action_decision", mutate)


def test_boolean_is_not_coerced_to_integer_or_number() -> None:
    _assert_invalid("dataset_profile", lambda value: value.update(row_count=True))


def test_arbitrary_object_is_not_coerced_to_string() -> None:
    _assert_invalid("report_draft", lambda value: value.update(title={"unsafe": "object"}))


def test_json_integer_is_accepted_for_schema_number_field() -> None:
    def mutate(value: dict[str, object]) -> None:
        value["safe_headroom"]["value"] = 1  # type: ignore[index]

    model = ActionDecision.model_validate(_mutated("action_decision", mutate))
    assert model.to_canonical_dict()["safe_headroom"]["value"] == 1  # type: ignore[index]


@pytest.mark.parametrize("nonfinite", [math.nan, math.inf, -math.inf])
def test_nonfinite_numbers_are_rejected(nonfinite: float) -> None:
    def mutate(value: dict[str, object]) -> None:
        value["safe_headroom"]["value"] = nonfinite  # type: ignore[index]

    _assert_invalid("action_decision", mutate)


def test_nonfinite_values_cannot_be_serialized() -> None:
    valid = ActionDecision.model_validate(_example("action_decision"))
    unsafe_headroom = valid.safe_headroom.model_copy(update={"value": math.nan})
    unsafe = valid.model_copy(update={"safe_headroom": unsafe_headroom})
    with pytest.raises(ValueError):
        unsafe.to_canonical_json()


def test_invalid_pattern_identifier_fails() -> None:
    _assert_invalid("action_decision", lambda value: value.update(run_id="run-not-canonical"))


def test_minimum_and_maximum_numeric_violations_fail() -> None:
    def mutate(value: dict[str, object]) -> None:
        value["policy"]["alpha"] = 0.5  # type: ignore[index]

    _assert_invalid("audit_contract", mutate)


def test_maximum_string_length_violation_fails() -> None:
    _assert_invalid("report_draft", lambda value: value.update(title="x" * 201))


def test_array_minimum_violation_fails() -> None:
    _assert_invalid("candidate_registry", lambda value: value.update(candidates=[]))


def test_array_maximum_violation_fails() -> None:
    def mutate(value: dict[str, object]) -> None:
        value["reason_codes"] = [f"REASON_{index:02d}" for index in range(51)]

    _assert_invalid("action_decision", mutate)


def test_required_field_omission_fails() -> None:
    def omit(value: dict[str, object]) -> None:
        value.pop("row_count")

    _assert_invalid("dataset_profile", omit)


def test_const_and_schema_version_violations_fail() -> None:
    _assert_invalid("run_manifest", lambda value: value.update(schema_version="2.0.0"))


def test_failed_protocol_result_preserves_null_results() -> None:
    def mutate(value: dict[str, object]) -> None:
        result = value["results"][0]  # type: ignore[index]
        result.update(status="failed", point_estimate=None, uncertainty=None)

    model = ProtocolResult.model_validate(_mutated("protocol_result", mutate))
    first = model.to_canonical_dict()["results"][0]  # type: ignore[index]
    assert first["status"] == "failed"
    assert first["point_estimate"] is None
    assert first["uncertainty"] is None


def test_ineligible_protocol_result_preserves_null_and_reason_fields() -> None:
    def mutate(value: dict[str, object]) -> None:
        result = value["results"][0]  # type: ignore[index]
        result.update(
            status="ineligible",
            point_estimate=None,
            uncertainty=None,
            warnings=[
                {
                    "code": "ORDER_UNAVAILABLE",
                    "severity": "warning",
                    "message": "Confirmed order was unavailable.",
                }
            ],
        )

    first = ProtocolResult.model_validate(_mutated("protocol_result", mutate)).to_canonical_dict()[
        "results"
    ][0]  # type: ignore[index]
    assert first["status"] == "ineligible"
    assert first["point_estimate"] is None
    assert first["warnings"][0]["code"] == "ORDER_UNAVAILABLE"


def test_near_tie_state_preserves_all_equivalent_candidates() -> None:
    model = RiecSelection.model_validate(_example("riec_selection"))
    result = model.to_canonical_dict()
    assert result["decision_status"] == "near_tie"
    assert result["equivalence_set"] == [
        "M2_product_stream",
        "M4_product_stream_shift",
    ]


@pytest.mark.parametrize("headroom", [0, None])
def test_action_decision_does_not_create_a_supported_pilot_range(
    headroom: int | None,
) -> None:
    def mutate(value: dict[str, object]) -> None:
        value.update(state="no_actionable_headroom", pilot_reference=None)
        safe_headroom = cast(dict[str, object], value["safe_headroom"])
        safe_headroom.update(
            value=headroom,
            basis="none" if headroom is None else "point_estimates_without_bound",
            eligible_protocol_ids=[],
        )

    result = ActionDecision.model_validate(_mutated("action_decision", mutate)).to_canonical_dict()
    assert result["pilot_reference"] is None
    assert result["safe_headroom"]["value"] is headroom  # type: ignore[index]


def test_evidence_ledger_preserves_parent_links_and_open_payload_objects() -> None:
    model = EvidenceLedger.model_validate(_example("evidence_ledger"))
    result = model.to_canonical_dict()
    assert result["items"][1]["parent_evidence_ids"] == ["EV-PROFILE-91C7DB559190"]  # type: ignore[index]
    assert result["items"][1]["value"]["equivalence_set"] == [  # type: ignore[index]
        "M2_product_stream",
        "M4_product_stream_shift",
    ]


def test_report_draft_preserves_evidence_bindings_and_placeholders() -> None:
    result = (
        get_canonical_model("report_draft")
        .model_validate(_example("report_draft"))
        .to_canonical_dict()
    )
    assert result["numeric_bindings"][0]["placeholder"] == "{{action_state}}"  # type: ignore[index]
    assert (
        "{{safe_headroom}}"
        in result["sections"][0]["paragraphs"][0][  # type: ignore[index]
            "text_template"
        ]
    )


def test_claim_audit_preserves_all_fixed_classification_categories() -> None:
    def mutate(value: dict[str, object]) -> None:
        claims = cast(list[dict[str, object]], value["claims"])
        for index, classification in enumerate(
            ("unsupported", "overstated", "prohibited"), start=5
        ):
            claims.append(
                {
                    "claim_id": f"CLM-{index:03d}",
                    "text": f"Synthetic {classification} claim.",
                    "materiality": "supporting",
                    "classification": classification,
                    "reason_code": "SYNTHETIC_NEGATIVE_CASE",
                    "evidence_ids": [],
                    "required_qualifier": None,
                    "replacement_text": None,
                }
            )
        value.update(overall_status="block", export_allowed=False)

    result = ClaimAudit.model_validate(_mutated("claim_audit", mutate)).to_canonical_dict()
    claims = cast(list[dict[str, object]], result["claims"])
    assert {claim["classification"] for claim in claims} == {
        "supported",
        "conditional",
        "unsupported",
        "overstated",
        "prohibited",
    }


@pytest.mark.parametrize("status", ["completed", "completed_with_warnings", "failed"])
def test_run_manifest_preserves_terminal_status_and_fallback_records(status: str) -> None:
    model = RunManifest.model_validate(
        _mutated("run_manifest", lambda value: value.update(status=status))
    )
    result = model.to_canonical_dict()
    assert result["status"] == status
    assert result["fallbacks"][0]["honesty_label"] == "Contract mode: versioned built-in."  # type: ignore[index]


def test_canonical_error_envelope_validates_against_schema() -> None:
    record = load_schema_registry().lookup("error_envelope")
    model = ErrorEnvelope.model_validate(record.example())
    result = model.to_canonical_dict()
    Draft202012Validator(record.validation_schema()).validate(result)
    assert result == record.example()


def test_application_errors_convert_to_canonical_envelopes_with_legacy_view() -> None:
    error = ApplicationError(
        ErrorCode.MALFORMED_CSV, "The uploaded CSV is malformed.", field="upload"
    )
    envelope = error.to_envelope()
    assert isinstance(envelope, ErrorEnvelope)
    assert envelope.code == "malformed_csv"
    assert envelope.details == {"field": "upload"}
    assert envelope.to_canonical_dict()["code"] == "MALFORMED_CSV"


def test_existing_upload_root_and_cleanup_error_codes_remain_unchanged() -> None:
    assert {code.name: code.value for code in ErrorCode} == {
        "UNSUPPORTED_FILE_TYPE": "unsupported_file_type",
        "ARCHIVE_UPLOAD_REJECTED": "archive_upload_rejected",
        "UPLOAD_TOO_LARGE": "upload_too_large",
        "TOO_MANY_ROWS": "too_many_rows",
        "TOO_MANY_COLUMNS": "too_many_columns",
        "MALFORMED_CSV": "malformed_csv",
        "UNSAFE_DISPLAY_FILENAME": "unsafe_display_filename",
        "BINARY_OR_NUL_CONTENT": "binary_or_nul_content",
        "SOURCE_NOT_FOUND": "source_not_found",
        "RUN_NOT_FOUND": "run_not_found",
        "STORAGE_FAILURE": "storage_failure",
        "CLEANUP_FAILURE": "cleanup_failure",
    }


def test_error_conversion_does_not_expose_paths_secrets_or_raw_causes() -> None:
    sensitive_path = "/" + "/".join(("Users", "operator", "private.csv"))
    secret = "sk-" + "sensitivevalue123456"
    error = ApplicationError(
        ErrorCode.STORAGE_FAILURE,
        f"failed at {sensitive_path} with {secret}",
        field=sensitive_path,
    )
    public_json = error.to_envelope().to_canonical_json()
    assert sensitive_path not in public_json
    assert secret not in public_json
    internal = error_envelope_from_exception(
        RuntimeError(f"cause {secret}"), stage=ErrorStage.REPORT
    )
    assert secret not in internal.to_canonical_json()
    assert internal.to_canonical_dict()["cause_chain"] == ["RuntimeError"]


def test_generated_error_ids_match_the_canonical_pattern() -> None:
    envelope = ApplicationError(ErrorCode.RUN_NOT_FOUND, "Run not found.").to_envelope()
    assert envelope.error_id.startswith("ERR-")
    assert len(envelope.error_id) == 16
    int(envelope.error_id.removeprefix("ERR-"), 16)


def test_returned_models_and_open_payloads_are_immutable() -> None:
    decision = ActionDecision.model_validate(_example("action_decision"))
    ledger = EvidenceLedger.model_validate(_example("evidence_ledger"))
    with pytest.raises(ValidationError):
        decision.state = "invalid_contract"  # type: ignore[assignment]
    with pytest.raises(TypeError):
        ledger.items[1].value["raw"] = "mutated"  # type: ignore[index]


def test_canonical_serialization_is_deterministic_sorted_compact_json() -> None:
    model = DatasetProfile.model_validate(_example("dataset_profile"))
    first = model.to_canonical_json()
    second = model.to_canonical_json()
    assert first == second
    assert first == json.dumps(
        model.to_canonical_dict(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    assert ": " not in first


def test_model_registry_and_schema_registry_have_one_to_one_canonical_coverage() -> None:
    schema_registry = load_schema_registry()
    canonical_records = {
        record.logical_name
        for record in schema_registry.canonical()
        if record.kind is SchemaKind.CANONICAL
    }
    assert canonical_records == set(CANONICAL_MODEL_REGISTRY)


def test_validation_errors_are_stable_and_hide_sensitive_payloads() -> None:
    secret = "sk-" + "payloadmustnotappear123"
    invalid = _example("error_envelope")
    invalid["unexpected"] = {"secret": secret}
    messages: list[str] = []
    for _ in range(2):
        with pytest.raises(ValidationError) as exc_info:
            ErrorEnvelope.model_validate(invalid)
        messages.append(str(exc_info.value))
    assert messages[0] == messages[1]
    assert secret not in messages[0]
    assert "canonical schema validation failed at root" in messages[0]
