"""Allowlisted evidence contexts and deterministically validated decision memos."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from decimal import Decimal, InvalidOperation

from riec_guard.benchmarks.catalog import validate_benchmark_identity
from riec_guard.benchmarks.models import (
    DemoBenchmarkSummary,
    RecordedScenarioSummary,
    ScenarioCatalog,
    ScenarioId,
)
from riec_guard.contract.models import (
    ActionDecision,
    ActionState,
    AuditContract,
    ConfirmationStatus,
    DatasetProfile,
    ProtocolId,
    ProtocolResult,
    RiecSelection,
)
from riec_guard.errors import ErrorClass, ErrorEnvelope
from riec_guard.evidence.ids import verify_evidence_item
from riec_guard.evidence.ledger import verify_ledger
from riec_guard.evidence.models import EvidenceComponent, EvidenceLedger
from riec_guard.gpt.client import StructuredGptClient, structured_response_is_bound
from riec_guard.gpt.models import (
    ARTIFACT_VERSION,
    MEMO_PROMPT_VERSION,
    DecisionMemo,
    DecisionMemoBody,
    EvidenceContext,
    EvidenceDescriptor,
    EvidenceFact,
    FactType,
    GptCallStatus,
    GptTask,
    gpt_error,
)
from riec_guard.gpt.sanitizer import GptPayloadBoundaryError, payload_sha256

MANDATORY_LIMITATIONS = (
    "This is retrospective screening analysis only.",
    "No autonomous control or compliance certification is provided.",
    "There is no evidence of achieved savings or a direct production setpoint recommendation.",
    "Any pilot range is a retrospective screening reference requiring a controlled pilot and engineering review.",
)

_NUMERIC_PATTERN = re.compile(r"(?<![A-Za-z0-9_])(?:\d+(?:\.\d+)?|\.\d+)%?")
_IDENTIFIER_PATTERN = re.compile(
    r"\b(?:EV-[A-Z0-9_]+-[A-F0-9]{12}|(?:AC|CTX)-[A-F0-9]{12}|"
    r"(?:FND|CLM)-\d{3}|[DHUG]\d+|M\d+_[a-z0-9_]+)\b"
)
_PROTOCOL_PATTERN = re.compile(r"\b([DHUG]\d+)\b")
_EVIDENCE_TEXT_PATTERN = re.compile(r"\bEV-[A-Z0-9_]{2,16}-[A-F0-9]{12}\b")
_FACT_TEXT_PATTERN = re.compile(r"\b(?:action|gate|policy|profile|protocol|riec)\.[A-Za-z0-9_.]+\b")
_KNOWN_UNIT_PATTERN = re.compile(r"(?<![A-Za-z])(?:mL|µL|μL|mg|kg|lb|oz|L|g)(?![A-Za-z])")
_ACTION_LABELS = tuple(state.value for state in ActionState)


class _FactCollector:
    def __init__(self) -> None:
        self.facts: list[EvidenceFact] = []

    def add(
        self,
        key: str,
        display: str,
        numeric: int | float | None,
        unit: str | None,
        evidence_ids: Sequence[str],
        fact_type: FactType,
    ) -> None:
        del numeric
        self.facts.append(
            EvidenceFact.model_validate(
                {
                    "fact_key": key,
                    "display_value": display,
                    "unit": unit,
                    "evidence_ids": tuple(evidence_ids),
                    "fact_type": fact_type,
                }
            )
        )


def build_evidence_context(
    *,
    dataset_profile: DatasetProfile,
    contract: AuditContract,
    selection: RiecSelection,
    protocols: ProtocolResult,
    action: ActionDecision,
    evidence_ledger: EvidenceLedger,
    limitations: Sequence[str] = (),
    scenario_id: str | None = None,
) -> EvidenceContext:
    """Project accepted canonical artifacts into a row-free fact allowlist."""

    if not all(
        (
            isinstance(dataset_profile, DatasetProfile),
            isinstance(contract, AuditContract),
            isinstance(selection, RiecSelection),
            isinstance(protocols, ProtocolResult),
            isinstance(action, ActionDecision),
            isinstance(evidence_ledger, EvidenceLedger),
        )
    ):
        raise TypeError("canonical deterministic artifacts are required")
    verify_ledger(evidence_ledger)
    for item in evidence_ledger.items:
        verify_evidence_item(item)
    if (
        contract.confirmation.status is not ConfirmationStatus.CONFIRMED
        or contract.contract_id != protocols.contract_id
        or contract.contract_id != action.contract_id
        or dataset_profile.dataset_id != contract.source.dataset_id
        or dataset_profile.dataset_sha256 != contract.source.dataset_sha256
        or selection.run_id != protocols.run_id
        or selection.run_id != action.run_id
        or selection.run_id != evidence_ledger.run_id
    ):
        raise ValueError("deterministic artifacts do not share one confirmed identity")

    components = {item.component: item for item in evidence_ledger.items}
    required_components = {
        EvidenceComponent.RIEC,
        EvidenceComponent.PROTOCOL,
        EvidenceComponent.ACTION,
    }
    if set(components) != required_components:
        raise ValueError("the GPT context requires the aggregate RIEC/protocol/action chain")
    riec_id = components[EvidenceComponent.RIEC].evidence_id
    protocol_id = components[EvidenceComponent.PROTOCOL].evidence_id
    action_id = components[EvidenceComponent.ACTION].evidence_id
    if (
        tuple(selection.evidence_ids) != (riec_id,)
        or any(protocol_id not in entry.evidence_ids for entry in protocols.results)
        or set(action.evidence_ids) != {riec_id, protocol_id, action_id}
    ):
        raise ValueError("deterministic artifact citations do not match the aggregate chain")

    facts = _FactCollector()
    _add_shared_profile_policy_facts(facts, dataset_profile, contract, riec_id, protocol_id)
    _add_selection_facts(
        facts,
        winner=selection.raw_numeric_winner,
        runner_up=selection.runner_up,
        near_tie=selection.decision_status.value == "near_tie",
        evidence_id=riec_id,
    )
    entries = {entry.protocol_id: entry for entry in protocols.results}
    for short, identifier in (
        ("H1", ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE),
        ("H2", ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL),
        ("H3", ProtocolId.H3_STUDENT_T_RESIDUAL_TAIL),
    ):
        entry = entries.get(identifier)
        if entry is not None:
            _add_protocol_fact(
                facts, short, entry.point_estimate, entry.unit, entry.status.value, protocol_id
            )
    bootstrap = entries.get(ProtocolId.U1_GROUP_BOOTSTRAP_BOUND)
    if bootstrap is not None:
        lower = bootstrap.uncertainty.lower if bootstrap.uncertainty is not None else None
        _add_protocol_fact(facts, "U1", lower, bootstrap.unit, bootstrap.status.value, protocol_id)
    facts.add(
        "gate.G1.status",
        action.gates.ordered_stability.value,
        None,
        None,
        (protocol_id,),
        FactType.GATE,
    )
    facts.add(
        "gate.G2.status",
        "supported" if action.gates.evidence_sufficient else "not_supported",
        None,
        None,
        (protocol_id,),
        FactType.GATE,
    )
    _add_action_facts(facts, action, action_id, protocol_id)
    descriptors = tuple(
        EvidenceDescriptor.model_validate(
            {
                "evidence_id": evidence_id,
                "component": component,
                "description": description,
            }
        )
        for evidence_id, component, description in (
            (riec_id, "RIEC", "Aggregate grouped RIEC-L1 selection evidence."),
            (protocol_id, "PROTOCOL", "Aggregate Fill protocol and gate evidence."),
            (action_id, "ACTION", "Aggregate deterministic action-decision evidence."),
        )
    )
    return _seal_context(
        scenario_id=scenario_id,
        dataset_sha256=dataset_profile.dataset_sha256,
        contract_id=contract.contract_id,
        action_state=action.state,
        facts=tuple(facts.facts),
        descriptors=descriptors,
        limitations=_bounded_limitations(limitations),
    )


def build_recorded_evidence_context(
    *,
    dataset_profile: DatasetProfile,
    catalog: ScenarioCatalog,
    benchmark_summary: DemoBenchmarkSummary,
    scenario_id: ScenarioId | str,
) -> EvidenceContext:
    """Build a context from the committed, identity-checked Macro-03 display record."""

    if not isinstance(dataset_profile, DatasetProfile):
        raise TypeError("a typed dataset profile is required")
    validate_benchmark_identity(benchmark_summary, catalog=catalog)
    selected = ScenarioId(scenario_id)
    record = next(item for item in benchmark_summary.scenarios if item.scenario_id is selected)
    definition = next(item for item in catalog.scenarios if item.scenario_id is selected)
    if (
        dataset_profile.dataset_sha256 != record.dataset_sha256
        or dataset_profile.row_count != record.row_count
        or definition.policy != benchmark_summary.shared_policy
    ):
        raise ValueError("recorded scenario, profile, and policy identities do not match")
    _validate_recorded_chain(record)

    riec_id = record.riec_evidence_id
    protocol_id = record.protocol_evidence_id
    action_id = record.action_evidence_id
    policy = benchmark_summary.shared_policy
    facts = _FactCollector()
    facts.add(
        "profile.row_count",
        str(record.row_count),
        record.row_count,
        None,
        (riec_id,),
        FactType.PROFILE,
    )
    facts.add(
        "profile.column_count",
        str(len(dataset_profile.column_profiles)),
        len(dataset_profile.column_profiles),
        None,
        (riec_id,),
        FactType.PROFILE,
    )
    facts.add(
        "profile.deployment_group_count",
        str(record.deployment_group_count),
        record.deployment_group_count,
        None,
        (riec_id,),
        FactType.PROFILE,
    )
    facts.add(
        "profile.product_count",
        str(record.product_count),
        record.product_count,
        None,
        (riec_id,),
        FactType.PROFILE,
    )
    for key, value in (
        ("policy.nominal_quantity", policy.nominal_quantity),
        ("policy.lower_limit", policy.lower_limit),
        ("policy.measurement_resolution", policy.measurement_resolution),
        ("policy.minimum_actionable_shift", policy.minimum_actionable_shift),
        ("policy.maximum_screening_shift", policy.maximum_screening_shift),
    ):
        facts.add(
            key, _display(value, policy.unit), value, policy.unit, (protocol_id,), FactType.POLICY
        )
    facts.add(
        "policy.alpha",
        _format_number(policy.alpha, 2),
        policy.alpha,
        None,
        (protocol_id,),
        FactType.POLICY,
    )
    _add_selection_facts(
        facts,
        winner=record.riec_winner,
        runner_up=record.riec_runner_up,
        near_tie=record.riec_near_tie,
        evidence_id=riec_id,
    )
    for short, display in (("H1", record.h1), ("H2", record.h2), ("H3", record.h3)):
        _add_protocol_fact(
            facts, short, display.value, display.unit, display.status.value, protocol_id
        )
    _add_protocol_fact(
        facts, "U1", record.u1.lower_bound, record.unit, record.u1.status.value, protocol_id
    )
    facts.add("gate.G1.status", record.g1_state.value, None, None, (protocol_id,), FactType.GATE)
    facts.add(
        "gate.G2.status",
        "supported" if record.g2.action_supported else "not_supported",
        None,
        None,
        (protocol_id,),
        FactType.GATE,
    )
    facts.add(
        "protocol.conflict",
        str(record.protocol_conflict).lower(),
        None,
        None,
        (protocol_id,),
        FactType.PROTOCOL,
    )
    if record.protocol_spread is not None:
        facts.add(
            "protocol.spread",
            _display(record.protocol_spread, record.unit),
            record.protocol_spread,
            record.unit,
            (protocol_id,),
            FactType.PROTOCOL,
        )
    facts.add("action.state", record.action_state.value, None, None, (action_id,), FactType.ACTION)
    facts.add(
        "action.decisive_reason", record.decisive_reason, None, None, (action_id,), FactType.ACTION
    )
    if record.pilot_min is not None and record.pilot_max is not None:
        facts.add(
            "action.pilot_min",
            _display(record.pilot_min, record.unit),
            record.pilot_min,
            record.unit,
            (action_id,),
            FactType.ACTION,
        )
        facts.add(
            "action.pilot_max",
            _display(record.pilot_max, record.unit),
            record.pilot_max,
            record.unit,
            (action_id,),
            FactType.ACTION,
        )
    descriptors = tuple(
        EvidenceDescriptor.model_validate(
            {
                "evidence_id": item.evidence_id,
                "component": item.component,
                "description": {
                    "RIEC": "Recorded aggregate grouped RIEC-L1 selection evidence.",
                    "PROTOCOL": "Recorded aggregate Fill protocol and gate evidence.",
                    "ACTION": "Recorded aggregate deterministic action-decision evidence.",
                }[item.component],
            }
        )
        for item in record.evidence_chain
    )
    return _seal_context(
        scenario_id=selected.value,
        dataset_sha256=dataset_profile.dataset_sha256,
        contract_id=record.contract_id,
        action_state=record.action_state,
        facts=tuple(facts.facts),
        descriptors=descriptors,
        limitations=_bounded_limitations((*catalog.limitations, *benchmark_summary.limitations)),
    )


def draft_decision_memo(
    *,
    evidence_context: EvidenceContext,
    client: StructuredGptClient,
) -> DecisionMemo | ErrorEnvelope:
    """Draft and independently validate one evidence-linked memo."""

    try:
        validate_evidence_context(evidence_context)
        payload = {"evidence_context": evidence_context.to_canonical_dict()}
        result = client.generate(
            task=GptTask.DECISION_MEMO,
            prompt_version=MEMO_PROMPT_VERSION,
            payload=payload,
            output_model=DecisionMemoBody,
        )
    except GptPayloadBoundaryError:
        return gpt_error(
            "GPT_MEMO_PRIVACY_BLOCK",
            "The evidence context could not cross the bounded GPT data boundary.",
            error_class=ErrorClass.PRIVACY_BLOCK,
            recoverable=True,
            user_action="Rebuild the evidence context from allowlisted aggregate facts.",
        )
    except (TypeError, ValueError):
        return gpt_error(
            "GPT_EVIDENCE_CONTEXT_INVALID",
            "The evidence context failed deterministic identity or boundary validation.",
            error_class=ErrorClass.SECURITY_BLOCK,
            recoverable=False,
            user_action="Regenerate the context from accepted deterministic artifacts.",
        )
    if not structured_response_is_bound(
        result,
        task=GptTask.DECISION_MEMO,
        prompt_version=MEMO_PROMPT_VERSION,
        payload=payload,
        output_model=DecisionMemoBody,
    ):
        return gpt_error(
            "GPT_MEMO_RESPONSE_UNBOUND",
            "The memo response metadata failed provenance validation.",
            error_class=ErrorClass.SECURITY_BLOCK,
            recoverable=False,
            user_action="Discard the response and retry with the fixed client adapter.",
        )
    if result.metadata.status is not GptCallStatus.SUCCESS or result.output is None:
        return gpt_error(
            "GPT_MEMO_UNAVAILABLE",
            "Deterministic audit complete; narrative assistance unavailable.",
            error_class=ErrorClass.API_UNAVAILABLE,
            recoverable=True,
            user_action="Retry narrative assistance later; deterministic results remain valid.",
            safe_details={
                "call_status": result.metadata.status.value,
                "transport_code": result.metadata.error_code or "UNSPECIFIED",
            },
        )
    try:
        validate_memo_body(result.output, evidence_context)
    except ValueError:
        return gpt_error(
            "GPT_MEMO_SEMANTIC_REJECTED",
            "The proposed memo introduced an unsupported citation, number, unit, or action claim.",
            error_class=ErrorClass.API_INVALID_OUTPUT,
            recoverable=True,
            user_action="Request a new evidence-bound memo without changing deterministic results.",
        )
    body = result.output
    return DecisionMemo.model_validate(
        {
            "artifact_version": ARTIFACT_VERSION,
            "prompt_version": MEMO_PROMPT_VERSION,
            "action_state": evidence_context.action_state,
            "evidence_context_sha256": evidence_context.payload_sha256,
            "request": result.request,
            "response": result.metadata,
            "title": body.title,
            "decision_snapshot": body.decision_snapshot,
            "what_the_evidence_shows": body.what_the_evidence_shows,
            "why_protocol_choice_matters": body.why_protocol_choice_matters,
            "recommended_next_step": body.recommended_next_step,
            "limitations": body.limitations,
            "findings": body.findings,
        }
    )


def validate_evidence_context(context: EvidenceContext) -> None:
    if not isinstance(context, EvidenceContext):
        raise TypeError("a typed evidence context is required")
    payload = context.to_canonical_dict()
    payload.pop("context_id", None)
    payload.pop("payload_sha256", None)
    digest = payload_sha256(payload)
    if context.payload_sha256 != digest or context.context_id != f"CTX-{digest[:12].upper()}":
        raise ValueError("evidence context identity is invalid")
    fact_keys = tuple(fact.fact_key for fact in context.facts)
    descriptor_ids = tuple(item.evidence_id for item in context.evidence_descriptors)
    if len(set(fact_keys)) != len(fact_keys) or len(set(descriptor_ids)) != len(descriptor_ids):
        raise ValueError("evidence context identifiers must be unique")
    if set(descriptor_ids) != set(context.valid_evidence_ids):
        raise ValueError("evidence descriptor allowlist is inconsistent")
    if any(
        not set(fact.evidence_ids).issubset(context.valid_evidence_ids) for fact in context.facts
    ):
        raise ValueError("fact evidence is outside the allowlist")
    if context.valid_action_labels != (context.action_state.value,):
        raise ValueError("action allowlist is inconsistent")
    if context.valid_numeric_tokens != _numeric_tokens(context.facts):
        raise ValueError("numeric allowlist is inconsistent")
    if context.valid_units != _ordered_unique(fact.unit for fact in context.facts if fact.unit):
        raise ValueError("unit allowlist is inconsistent")
    if any(not value.strip() for value in context.limitations):
        raise ValueError("limitations cannot be blank")


def validate_memo_body(body: DecisionMemoBody, context: EvidenceContext) -> None:
    """Fail closed on citations, numbers, units, claims, and action semantics."""

    validate_evidence_context(context)
    text_fields = (
        body.title,
        body.decision_snapshot,
        body.what_the_evidence_shows,
        body.why_protocol_choice_matters,
        body.recommended_next_step,
        *body.limitations,
        *(finding.statement for finding in body.findings),
    )
    if any(not text.strip() for text in text_fields):
        raise ValueError("memo text cannot be blank")
    if set(body.limitations) != set(context.limitations):
        raise ValueError("memo limitations must equal the deterministic limitation allowlist")
    expected_ids = tuple(f"FND-{index:03d}" for index in range(1, len(body.findings) + 1))
    if tuple(finding.finding_id for finding in body.findings) != expected_ids:
        raise ValueError("memo finding IDs must be unique and ordered")
    facts = {fact.fact_key: fact for fact in context.facts}
    for finding in body.findings:
        if not set(finding.evidence_ids).issubset(context.valid_evidence_ids):
            raise ValueError("memo cites an unknown evidence ID")
        if not set(finding.fact_keys).issubset(facts):
            raise ValueError("memo cites an unknown fact key")
        required_evidence = {
            evidence_id for key in finding.fact_keys for evidence_id in facts[key].evidence_ids
        }
        if set(finding.evidence_ids) != required_evidence:
            raise ValueError("memo finding citations are incomplete or extraneous")
    substantive = "\n".join(text_fields)
    if _unknown_numbers(substantive, context.valid_numeric_tokens):
        raise ValueError("memo contains an unsupported numeric token")
    allowed_protocols = {
        key.split(".")[1] for key in facts if key.startswith(("protocol.", "gate."))
    }
    if any(token not in allowed_protocols for token in _PROTOCOL_PATTERN.findall(substantive)):
        raise ValueError("memo contains an unsupported protocol label")
    if any(unit not in context.valid_units for unit in _KNOWN_UNIT_PATTERN.findall(substantive)):
        raise ValueError("memo contains an unsupported unit")
    if any(
        evidence_id not in context.valid_evidence_ids
        for evidence_id in _EVIDENCE_TEXT_PATTERN.findall(substantive)
    ):
        raise ValueError("memo text contains an unknown evidence ID")
    if any(fact_key not in facts for fact_key in _FACT_TEXT_PATTERN.findall(substantive)):
        raise ValueError("memo text contains an unknown fact key")
    referenced_actions = {label for label in _ACTION_LABELS if label in substantive}
    if referenced_actions - {context.action_state.value}:
        raise ValueError("memo contains an action label that was not accepted")
    if _has_positive_prohibited_claim(substantive):
        raise ValueError("memo contains a prohibited product claim")
    _validate_action_semantics(body, context, facts)


def unknown_numeric_tokens(text: str, context: EvidenceContext) -> tuple[str, ...]:
    """Expose the same deterministic numeric check to the claim-audit layer."""

    validate_evidence_context(context)
    return _unknown_numbers(text, context.valid_numeric_tokens)


def _seal_context(
    *,
    scenario_id: str | None,
    dataset_sha256: str,
    contract_id: str,
    action_state: ActionState,
    facts: tuple[EvidenceFact, ...],
    descriptors: tuple[EvidenceDescriptor, ...],
    limitations: tuple[str, ...],
) -> EvidenceContext:
    ids = tuple(item.evidence_id for item in descriptors)
    value: dict[str, object] = {
        "artifact_version": ARTIFACT_VERSION,
        "context_version": "evidence-context.v1",
        "context_id": "CTX-000000000000",
        "scenario_id": scenario_id,
        "dataset_sha256": dataset_sha256,
        "contract_id": contract_id,
        "action_state": action_state,
        "facts": facts,
        "evidence_descriptors": descriptors,
        "valid_evidence_ids": ids,
        "valid_numeric_tokens": _numeric_tokens(facts),
        "valid_action_labels": (action_state.value,),
        "valid_units": _ordered_unique(fact.unit for fact in facts if fact.unit),
        "limitations": limitations,
        "payload_sha256": "0" * 64,
    }
    provisional = EvidenceContext.model_validate(value)
    hash_payload = provisional.to_canonical_dict()
    hash_payload.pop("context_id", None)
    hash_payload.pop("payload_sha256", None)
    digest = payload_sha256(hash_payload)
    value["context_id"] = f"CTX-{digest[:12].upper()}"
    value["payload_sha256"] = digest
    result = EvidenceContext.model_validate(value)
    validate_evidence_context(result)
    return result


def _add_shared_profile_policy_facts(
    facts: _FactCollector,
    profile: DatasetProfile,
    contract: AuditContract,
    riec_id: str,
    protocol_id: str,
) -> None:
    facts.add(
        "profile.row_count",
        str(profile.row_count),
        profile.row_count,
        None,
        (riec_id,),
        FactType.PROFILE,
    )
    facts.add(
        "profile.column_count",
        str(len(profile.column_profiles)),
        len(profile.column_profiles),
        None,
        (riec_id,),
        FactType.PROFILE,
    )
    unit = contract.measurement.unit
    for key, value in (
        ("policy.nominal_quantity", contract.policy.nominal_quantity),
        ("policy.lower_limit", contract.policy.lower_limit),
        ("policy.minimum_actionable_shift", contract.policy.minimum_actionable_shift),
        ("policy.maximum_screening_shift", contract.policy.maximum_screening_shift),
    ):
        facts.add(key, _display(value, unit), value, unit, (protocol_id,), FactType.POLICY)
    facts.add(
        "policy.alpha",
        _format_number(contract.policy.alpha, 4),
        contract.policy.alpha,
        None,
        (protocol_id,),
        FactType.POLICY,
    )
    if contract.measurement.measurement_resolution is not None:
        resolution = contract.measurement.measurement_resolution
        facts.add(
            "policy.measurement_resolution",
            _display(resolution, unit),
            resolution,
            unit,
            (protocol_id,),
            FactType.POLICY,
        )


def _add_selection_facts(
    facts: _FactCollector,
    *,
    winner: str | None,
    runner_up: str | None,
    near_tie: bool,
    evidence_id: str,
) -> None:
    facts.add("riec.winner", winner or "none", None, None, (evidence_id,), FactType.SELECTION)
    if runner_up is not None:
        facts.add("riec.runner_up", runner_up, None, None, (evidence_id,), FactType.SELECTION)
    facts.add(
        "riec.near_tie", str(near_tie).lower(), None, None, (evidence_id,), FactType.SELECTION
    )


def _add_protocol_fact(
    facts: _FactCollector,
    short: str,
    value: int | float | None,
    unit: str | None,
    status: str,
    evidence_id: str,
) -> None:
    facts.add(f"protocol.{short}.status", status, None, None, (evidence_id,), FactType.PROTOCOL)
    if value is not None:
        facts.add(
            f"protocol.{short}.headroom" if short != "U1" else "protocol.U1.lower_bound",
            _display(value, unit),
            value,
            unit,
            (evidence_id,),
            FactType.PROTOCOL,
        )


def _add_action_facts(
    facts: _FactCollector,
    action: ActionDecision,
    action_id: str,
    protocol_id: str,
) -> None:
    facts.add("action.state", action.state.value, None, None, (action_id,), FactType.ACTION)
    facts.add(
        "protocol.conflict",
        str(action.conflict.material_protocol_conflict).lower(),
        None,
        None,
        (protocol_id,),
        FactType.PROTOCOL,
    )
    if action.conflict.protocol_spread is not None:
        facts.add(
            "protocol.spread",
            _display(action.conflict.protocol_spread, action.safe_headroom.unit),
            action.conflict.protocol_spread,
            action.safe_headroom.unit,
            (protocol_id,),
            FactType.PROTOCOL,
        )
    if action.pilot_reference is not None:
        pilot = action.pilot_reference
        facts.add(
            "action.pilot_min",
            _display(pilot.lower, pilot.unit),
            pilot.lower,
            pilot.unit,
            (action_id,),
            FactType.ACTION,
        )
        facts.add(
            "action.pilot_max",
            _display(pilot.upper, pilot.unit),
            pilot.upper,
            pilot.unit,
            (action_id,),
            FactType.ACTION,
        )


def _validate_recorded_chain(record: RecordedScenarioSummary) -> None:
    expected = (
        ("RIEC", record.riec_evidence_id),
        ("PROTOCOL", record.protocol_evidence_id),
        ("ACTION", record.action_evidence_id),
    )
    observed = tuple((item.component, item.evidence_id) for item in record.evidence_chain)
    if observed != expected:
        raise ValueError("recorded evidence chain identifiers are inconsistent")


def _bounded_limitations(values: Iterable[str]) -> tuple[str, ...]:
    result = list(MANDATORY_LIMITATIONS)
    for value in values:
        if isinstance(value, str) and value.strip() and value not in result:
            result.append(value)
        if len(result) == 12:
            break
    return tuple(result)


def _numeric_tokens(facts: Sequence[EvidenceFact]) -> tuple[str, ...]:
    return _ordered_unique(
        match.group(0) for fact in facts for match in _NUMERIC_PATTERN.finditer(fact.display_value)
    )


def _unknown_numbers(text: str, allowed: Sequence[str]) -> tuple[str, ...]:
    masked = _IDENTIFIER_PATTERN.sub("", text)
    return tuple(
        token
        for token in (match.group(0) for match in _NUMERIC_PATTERN.finditer(masked))
        if not _number_is_allowed(token, allowed)
    )


def _number_is_allowed(token: str, allowed: Sequence[str]) -> bool:
    if token.endswith("%"):
        return token in allowed
    try:
        value = Decimal(token)
        return any(not item.endswith("%") and Decimal(item) == value for item in allowed)
    except InvalidOperation:
        return False


def _display(value: int | float, unit: str | None) -> str:
    rendered = _format_number(value, 2)
    return f"{rendered} {unit}" if unit else rendered


def _format_number(value: int | float, places: int) -> str:
    return f"{float(value):.{places}f}"


def _ordered_unique(values: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        if value not in result:
            result.append(value)
    return tuple(result)


def _has_positive_prohibited_claim(text: str) -> bool:
    direct = (
        "will save",
        "achieved savings",
        "guaranteed savings",
        "guaranteed safety",
        "is safe for production",
        "is compliant",
        "optimal production setpoint",
        "zero-risk",
        "zero risk",
        "successful live deployment",
        "universally validated",
        "universal validation achieved",
    )
    for sentence in re.split(r"[.!?;\n]+", text.casefold()):
        negated = any(
            marker in sentence
            for marker in (
                "no evidence of",
                "not evidence of",
                "does not",
                "do not",
                "is not",
                "are not",
                "no autonomous",
                "no direct",
            )
        )
        if not negated and any(phrase in sentence for phrase in direct):
            return True
        if "production setpoint" in sentence and not negated:
            return True
    return False


def _validate_action_semantics(
    body: DecisionMemoBody,
    context: EvidenceContext,
    facts: dict[str, EvidenceFact],
) -> None:
    text = " ".join(
        (
            body.decision_snapshot,
            body.what_the_evidence_shows,
            body.why_protocol_choice_matters,
            body.recommended_next_step,
        )
    ).casefold()
    cited_keys = {key for finding in body.findings for key in finding.fact_keys}
    state = context.action_state
    if state is ActionState.PILOT_RANGE_SUPPORTED:
        required = (
            "retrospective screening reference",
            "controlled pilot",
            "engineering review",
            "not a production setpoint",
        )
        if any(phrase not in text for phrase in required):
            raise ValueError("supported-pilot semantics are incomplete")
        if not {"action.pilot_min", "action.pilot_max"}.issubset(cited_keys):
            raise ValueError("supported pilot interval is not cited")
    elif state is ActionState.PILOT_ONLY_CONSERVATIVE:
        if (
            "conservative" not in text
            or not ({"protocol disagreement", "protocol conflict"} & set(_phrases(text)))
            or "full agreement" in text
            or "protocols agree" in text
            or "complete agreement" in text
            or "unanimous" in text
            or "controlled pilot" not in text
            or "not a production setpoint" not in text
            or not {"action.pilot_min", "action.pilot_max"}.issubset(cited_keys)
        ):
            raise ValueError("conservative-pilot semantics are incomplete")
    elif state is ActionState.DIAGNOSE_PROCESS_FIRST:
        if "no pilot interval" not in text or "process diagnosis" not in text:
            raise ValueError("diagnose-first semantics are incomplete")
        if {"action.pilot_min", "action.pilot_max"} & set(facts):
            raise ValueError("diagnose-first context cannot contain a pilot interval")
        if any(
            "pilot" in sentence and _NUMERIC_PATTERN.search(sentence)
            for sentence in re.split(r"[.!?;\n]+", text)
        ):
            raise ValueError("diagnose-first memo cannot infer a numeric pilot interval")
    elif state is ActionState.INSUFFICIENT_EVIDENCE:
        if "cannot support an action" not in text or "diagnostic headroom" not in text:
            raise ValueError("insufficient-evidence semantics are incomplete")
    elif state is ActionState.NO_ACTIONABLE_HEADROOM:
        if "no actionable headroom" not in text or "no pilot interval" not in text:
            raise ValueError("no-headroom semantics are incomplete")
    elif state is ActionState.INVALID_CONTRACT and "contract" not in text:
        raise ValueError("invalid-contract semantics are incomplete")


def _phrases(text: str) -> tuple[str, ...]:
    return tuple(
        phrase for phrase in ("protocol disagreement", "protocol conflict") if phrase in text
    )


__all__ = [
    "MANDATORY_LIMITATIONS",
    "build_evidence_context",
    "build_recorded_evidence_context",
    "draft_decision_memo",
    "unknown_numeric_tokens",
    "validate_evidence_context",
    "validate_memo_body",
]
