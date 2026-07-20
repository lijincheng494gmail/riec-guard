from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError, asdict, fields, is_dataclass
from pathlib import Path

import pytest

from riec_guard.contract.models import DatasetProfile
from riec_guard.errors import ErrorEnvelope
from riec_guard.gpt.models import EvidenceContext
from riec_guard.ui import backend
from riec_guard.ui.models import (
    UiClaimReview,
    UiDecisionSnapshot,
    UiDownloadPacket,
    UiEvidenceNode,
    UiGateStatus,
    UiGptCall,
    UiGptCapability,
    UiGptFinding,
    UiGptResult,
    UiGptRoleSuggestion,
    UiProtocolRow,
    UiScenarioBundle,
    UiScenarioDefinition,
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_SCENARIO_ORDER = (
    "stable_symmetric",
    "heavy_tail_particulate",
    "batch_drift_change_point",
)
_EXPECTED = {
    "stable_symmetric": {
        "display_name": "Stable symmetric process",
        "action_state": "pilot_range_supported",
        "action_label": "Controlled pilot range supported",
        "pilot": (0.15, 0.40),
        "conflict": False,
        "g1": "pass",
        "riec_winner": "M4_product_stream_shift",
        "h1": 0.5999999999999943,
        "h2": 0.5,
        "h3": 0.5,
    },
    "heavy_tail_particulate": {
        "display_name": "Heavy-tail particulate variation",
        "action_state": "pilot_only_conservative",
        "action_label": "Conservative pilot only",
        "pilot": (0.05, 0.14),
        "conflict": True,
        "g1": "pass",
        "riec_winner": "M4_product_stream_shift",
        "h1": 0.28999999999999204,
        "h2": 0.5,
        "h3": 0.5,
    },
    "batch_drift_change_point": {
        "display_name": "Batch drift and change point",
        "action_state": "diagnose_process_first",
        "action_label": "Diagnose process first",
        "pilot": (None, None),
        "conflict": True,
        "g1": "material_warning",
        "riec_winner": "M6_product_stream_shift_time",
        "h1": 0.6599999999999966,
        "h2": 0.5,
        "h3": None,
    },
}
_DISPLAY_MODEL_FIELDS = {
    UiScenarioDefinition: {
        "scenario_id",
        "scenario_version",
        "display_name",
        "mechanism_description",
        "domain_hint",
        "classification",
        "limitation",
    },
    UiDecisionSnapshot: {
        "action_state",
        "action_label",
        "decisive_reason",
        "pilot_min",
        "pilot_max",
        "unit",
        "protocol_conflict",
        "conflict_summary",
        "protocol_spread",
    },
    UiProtocolRow: {
        "protocol_id",
        "name",
        "status",
        "value",
        "lower_bound",
        "unit",
        "role_limitation",
    },
    UiGateStatus: {"gate_id", "status", "supports_action", "detail"},
    UiEvidenceNode: {
        "component",
        "evidence_id",
        "content_sha256",
        "parent_evidence_ids",
    },
    UiScenarioBundle: {
        "definition",
        "result_source",
        "source_explanation",
        "dataset_sha256",
        "catalog_sha256",
        "summary_sha256",
        "contract_id",
        "policy_profile_id",
        "row_count",
        "deployment_group_count",
        "product_count",
        "rows_per_product",
        "nominal_quantity",
        "lower_limit",
        "alpha",
        "measurement_resolution",
        "minimum_actionable_shift",
        "maximum_screening_shift",
        "protocol_spread_tolerance",
        "bootstrap_replicates",
        "bootstrap_seed",
        "riec_winner",
        "riec_runner_up",
        "riec_near_tie",
        "equivalence_set",
        "decision",
        "protocols",
        "gates",
        "bootstrap_requested",
        "bootstrap_successful",
        "bootstrap_failed",
        "evidence_nodes",
        "limitations",
    },
    UiGptCapability: {"title", "description"},
    UiGptRoleSuggestion: {"role", "column", "confidence", "reason"},
    UiGptFinding: {"finding_id", "statement", "evidence_ids", "fact_keys", "importance"},
    UiClaimReview: {
        "claim_id",
        "verdict",
        "reason",
        "evidence_ids",
        "fact_keys",
        "suggested_revision",
    },
    UiGptCall: {
        "task",
        "status",
        "execution_mode",
        "requested_model",
        "returned_model",
        "prompt_version",
        "response_id",
        "input_sha256",
        "output_sha256",
        "attempt_count",
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "error_code",
    },
    UiGptResult: {
        "scenario_id",
        "context_source",
        "mode_label",
        "status",
        "user_message",
        "fixture_non_live",
        "deterministic_analysis_available",
        "requested_model",
        "prompt_versions",
        "workflow_sha256",
        "contract_suggestions",
        "requires_human_confirmation",
        "analysis_permitted",
        "memo_title",
        "decision_snapshot",
        "evidence_summary",
        "protocol_explanation",
        "recommended_next_step",
        "memo_limitations",
        "findings",
        "claim_audit_status",
        "deterministic_validation_status",
        "claim_reviews",
        "referenced_evidence_ids",
        "calls",
    },
    UiDownloadPacket: {"filename", "media_type", "content", "content_sha256"},
}


def _bundle(scenario_id: str) -> UiScenarioBundle:
    result = backend.load_verified_recorded_scenario(scenario_id)
    assert isinstance(result, UiScenarioBundle), getattr(result, "code", None)
    return result


def _serialized_has_no_sensitive_runtime_material(value: object) -> None:
    serialized = json.dumps(value, ensure_ascii=False, sort_keys=True).casefold()
    prohibited = (
        str(_REPOSITORY_ROOT).casefold(),
        "/users/",
        "raw_rows",
        "row_predictions",
        "residual_array",
        "residuals",
        "full_prompt",
        "chain_of_thought",
        "stack_trace",
        "traceback",
        "openai_api_key",
        "authorization_header",
        "sk-secret-shaped",
        "batch_01",
        "product_a",
    )
    assert not any(token in serialized for token in prohibited)


def test_recorded_loader_verifies_exact_three_scenario_definitions() -> None:
    definitions = backend.load_verified_scenario_definitions()

    assert not isinstance(definitions, ErrorEnvelope)
    assert tuple(item.scenario_id for item in definitions) == _SCENARIO_ORDER
    assert tuple(item.display_name for item in definitions) == tuple(
        _EXPECTED[scenario_id]["display_name"] for scenario_id in _SCENARIO_ORDER
    )
    assert tuple(item.scenario_version for item in definitions) == ("1.0.0",) * 3
    assert all(item.classification == "public_synthetic" for item in definitions)
    assert all(isinstance(item, UiScenarioDefinition) for item in definitions)


@pytest.mark.parametrize("scenario_id", _SCENARIO_ORDER)
def test_recorded_bundle_preserves_exact_accepted_semantics(scenario_id: str) -> None:
    bundle = _bundle(scenario_id)
    expected = _EXPECTED[scenario_id]
    protocols = {row.protocol_id: row for row in bundle.protocols}
    gates = {gate.gate_id: gate for gate in bundle.gates}

    assert bundle.definition.display_name == expected["display_name"]
    assert bundle.result_source == "Recorded deterministic audit"
    assert "200 whole-group bootstrap replicates" in bundle.source_explanation
    assert bundle.row_count == 1056
    assert bundle.deployment_group_count == 12
    assert bundle.product_count == 2
    assert bundle.rows_per_product == 528
    assert bundle.alpha == 0.01
    assert bundle.bootstrap_replicates == 200
    assert bundle.bootstrap_requested == bundle.bootstrap_successful == 200
    assert bundle.bootstrap_failed == 0
    assert bundle.bootstrap_seed == 20260718
    assert bundle.policy_profile_id == "public-demo-policy.v1"
    assert bundle.decision.action_state == expected["action_state"]
    assert bundle.decision.action_label == expected["action_label"]
    assert (bundle.decision.pilot_min, bundle.decision.pilot_max) == expected["pilot"]
    assert bundle.decision.protocol_conflict is expected["conflict"]
    assert bundle.riec_winner == expected["riec_winner"]
    assert gates["G1"].status == expected["g1"]
    assert gates["G2"].status == "supported" and gates["G2"].supports_action
    assert tuple(protocols) == ("H1", "H2", "H3", "U1")
    assert protocols["H1"].value == expected["h1"]
    assert protocols["H2"].value == expected["h2"]
    assert protocols["H3"].value == expected["h3"]
    assert tuple(node.component for node in bundle.evidence_nodes) == (
        "RIEC",
        "PROTOCOL",
        "ACTION",
    )
    riec, protocol, action = bundle.evidence_nodes
    assert protocol.parent_evidence_ids == (riec.evidence_id,)
    assert set(action.parent_evidence_ids) == {riec.evidence_id, protocol.evidence_id}
    assert all(
        node.evidence_id.endswith(node.content_sha256[:12].upper())
        for node in bundle.evidence_nodes
    )
    if scenario_id == "batch_drift_change_point":
        assert not bundle.decision.has_pilot_interval
        assert protocols["H3"].status == "ineligible"
    else:
        assert bundle.decision.has_pilot_interval


@pytest.mark.parametrize(
    "scenario_id",
    (
        "../stable_symmetric",
        "stable_symmetric/../../private",
        "",
        "unknown",
        Path("stable_symmetric"),
    ),
)
def test_recorded_loader_fails_closed_for_unknown_or_path_shaped_input(
    scenario_id: object,
) -> None:
    result = backend.load_verified_recorded_scenario(scenario_id)  # type: ignore[arg-type]

    assert isinstance(result, ErrorEnvelope)
    assert result.code == "UI_SCENARIO_NOT_REGISTERED"
    assert result.safe_details == {}
    assert result.cause_chain == ()
    _serialized_has_no_sensitive_runtime_material(result.to_canonical_dict())


def test_display_models_are_frozen_slotted_and_explicitly_allowlisted() -> None:
    for model, expected_fields in _DISPLAY_MODEL_FIELDS.items():
        assert is_dataclass(model)
        assert getattr(model, "__dataclass_params__").frozen
        assert {field.name for field in fields(model)} == expected_fields
        assert "__dict__" not in getattr(model, "__slots__")
        assert not hasattr(model, "to_canonical_dict")
        assert not hasattr(model, "model_dump")

    definition = _bundle("stable_symmetric").definition
    with pytest.raises(FrozenInstanceError):
        definition.display_name = "mutated"  # type: ignore[misc]


@pytest.mark.parametrize("scenario_id", _SCENARIO_ORDER)
def test_download_is_deterministic_accurate_allowlisted_and_memory_only(
    scenario_id: str,
) -> None:
    bundle = _bundle(scenario_id)

    first = backend.build_download_packet(bundle)
    second = backend.build_download_packet(bundle)

    assert isinstance(first, UiDownloadPacket)
    assert first == second
    assert first.filename == f"riec_guard_{scenario_id}_decision.json"
    assert first.media_type == "application/json"
    assert first.content.endswith(b"\n")
    assert first.content_sha256 == hashlib.sha256(first.content).hexdigest()
    payload = json.loads(first.content)
    assert set(payload) == {
        "schema_version",
        "product",
        "scenario",
        "source",
        "design",
        "policy",
        "riec",
        "protocols",
        "gates",
        "conflict",
        "action",
        "limitations",
        "evidence",
        "gpt",
    }
    assert payload["scenario"]["scenario_id"] == scenario_id
    assert payload["source"]["dataset_sha256"] == bundle.dataset_sha256
    assert payload["source"]["contract_id"] == bundle.contract_id
    assert payload["action"]["state"] == bundle.decision.action_state
    assert payload["action"]["pilot_min"] == bundle.decision.pilot_min
    assert payload["action"]["pilot_max"] == bundle.decision.pilot_max
    assert payload["gpt"] is None
    assert len(payload["evidence"]) == 3
    _serialized_has_no_sensitive_runtime_material(payload)


@pytest.mark.parametrize("scenario_id", _SCENARIO_ORDER)
def test_fixture_gpt_projection_is_typed_evidence_bound_and_network_free(
    scenario_id: str,
) -> None:
    bundle = _bundle(scenario_id)

    result = backend.run_fixture_gpt_workflow(scenario_id)

    assert isinstance(result, UiGptResult), getattr(result, "code", None)
    assert result.scenario_id == scenario_id
    assert result.context_source == "recorded_production_default"
    assert result.mode_label == "Fixture / non-live"
    assert result.status == "completed"
    assert result.fixture_non_live
    assert result.deterministic_analysis_available
    assert result.requested_model == "gpt-5.6"
    assert result.prompt_versions == (
        "contract-assistant.v1",
        "decision-memo.v1",
        "claim-auditor.v1",
    )
    assert len(result.calls) == 3
    assert all(call.execution_mode == "fixture" for call in result.calls)
    assert all(call.requested_model == "gpt-5.6" for call in result.calls)
    assert result.requires_human_confirmation is True
    assert result.analysis_permitted is False
    assert result.memo_title is not None
    assert result.claim_audit_status == "pass"
    assert result.deterministic_validation_status == "passed"
    valid_ids = {node.evidence_id for node in bundle.evidence_nodes}
    assert set(result.referenced_evidence_ids).issubset(valid_ids)
    assert all(set(item.evidence_ids).issubset(valid_ids) for item in result.findings)
    assert all(set(item.evidence_ids).issubset(valid_ids) for item in result.claim_reviews)
    _serialized_has_no_sensitive_runtime_material(asdict(result))

    packet = backend.build_download_packet(bundle, gpt_result=result)
    assert isinstance(packet, UiDownloadPacket)
    payload = json.loads(packet.content)
    assert payload["action"]["state"] == bundle.decision.action_state
    assert payload["gpt"]["requested_model"] == "gpt-5.6"
    assert payload["gpt"]["fixture_non_live"] is True
    _serialized_has_no_sensitive_runtime_material(payload)


@pytest.mark.parametrize("scenario_id", _SCENARIO_ORDER)
def test_recorded_gpt_context_contains_only_sanitized_profile_and_aggregate_evidence(
    scenario_id: str,
) -> None:
    bundle = _bundle(scenario_id)

    prepared = backend._prepare_gpt_context(scenario_id)

    assert not isinstance(prepared, ErrorEnvelope)
    profile, context = prepared
    assert isinstance(profile, DatasetProfile)
    assert isinstance(context, EvidenceContext)
    assert context.scenario_id == scenario_id
    assert context.dataset_sha256 == bundle.dataset_sha256
    assert context.contract_id == bundle.contract_id
    assert context.action_state.value == bundle.decision.action_state
    assert set(context.valid_evidence_ids) == {node.evidence_id for node in bundle.evidence_nodes}
    redaction = profile.privacy_redaction
    assert redaction.raw_rows_included is False
    assert redaction.direct_identifiers_included is False
    assert redaction.high_cardinality_values_included is False
    _serialized_has_no_sensitive_runtime_material(context.to_canonical_dict())
