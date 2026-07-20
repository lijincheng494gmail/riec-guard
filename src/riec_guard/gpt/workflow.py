"""Safe orchestration for advisory contract, memo, and claim-audit stages."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from riec_guard.contract.models import ActionState, DatasetProfile
from riec_guard.errors import CanonicalModel, ErrorClass, ErrorEnvelope
from riec_guard.gpt.claim_auditor import audit_memo_claims
from riec_guard.gpt.client import (
    FixtureStructuredGptClient,
    StructuredGptClient,
    structured_response_is_bound,
)
from riec_guard.gpt.contract_assistant import suggest_contract_mapping
from riec_guard.gpt.memo import draft_decision_memo, validate_evidence_context
from riec_guard.gpt.models import (
    ARTIFACT_VERSION,
    DEFAULT_GPT_MODEL,
    PROMPT_VERSIONS,
    ClaimAuditBody,
    ClaimAuditResult,
    ClaimAuditStatus,
    ContractRole,
    ContractSuggestion,
    ContractSuggestionBody,
    DecisionMemo,
    DecisionMemoBody,
    EvidenceContext,
    GptCallStatus,
    GptExecutionMode,
    GptResponseMetadata,
    GptTask,
    GptWorkflowResult,
    GptWorkflowStatus,
    OutputT,
    StructuredGptResponse,
    gpt_error,
)
from riec_guard.gpt.sanitizer import payload_sha256


class _RecordingClient:
    """Record only response metadata bound to the exact delegated call."""

    def __init__(self, delegate: StructuredGptClient) -> None:
        self._delegate = delegate
        self._responses: list[GptResponseMetadata] = []

    @property
    def responses(self) -> tuple[GptResponseMetadata, ...]:
        return tuple(self._responses)

    def generate(
        self,
        *,
        task: GptTask,
        prompt_version: str,
        payload: Mapping[str, object],
        output_model: type[OutputT],
    ) -> StructuredGptResponse[OutputT]:
        result = self._delegate.generate(
            task=task,
            prompt_version=prompt_version,
            payload=payload,
            output_model=output_model,
        )
        if structured_response_is_bound(
            result,
            task=task,
            prompt_version=prompt_version,
            payload=payload,
            output_model=output_model,
        ):
            self._responses.append(result.metadata)
        return result


def run_gpt_interpretation_workflow(
    *,
    dataset_profile: DatasetProfile,
    evidence_context: EvidenceContext,
    client: StructuredGptClient,
) -> GptWorkflowResult | ErrorEnvelope:
    """Explain accepted results without feeding GPT output back into analysis."""

    try:
        validate_evidence_context(evidence_context)
        if not isinstance(dataset_profile, DatasetProfile):
            raise TypeError("a typed dataset profile is required")
        fact_values = {fact.fact_key: fact.display_value for fact in evidence_context.facts}
        if (
            evidence_context.dataset_sha256 != dataset_profile.dataset_sha256
            or fact_values.get("profile.row_count") != str(dataset_profile.row_count)
            or fact_values.get("profile.column_count") != str(len(dataset_profile.column_profiles))
        ):
            raise ValueError("dataset profile and evidence context identities do not match")
    except (TypeError, ValueError):
        return gpt_error(
            "GPT_WORKFLOW_CONTEXT_INVALID",
            "The GPT workflow rejected an invalid evidence context.",
            error_class=ErrorClass.SECURITY_BLOCK,
            recoverable=False,
            user_action="Regenerate the context from accepted deterministic artifacts.",
        )
    recorder = _RecordingClient(client)
    contract = suggest_contract_mapping(dataset_profile=dataset_profile, client=recorder)
    fixture_client = isinstance(client, FixtureStructuredGptClient)
    if isinstance(contract, ErrorEnvelope):
        return _workflow_result(
            status=GptWorkflowStatus.NARRATIVE_UNAVAILABLE,
            contract=None,
            memo=None,
            audit=None,
            audit_trail=recorder.responses,
            failure_stage=GptTask.CONTRACT_ASSISTANT,
            message="Deterministic audit complete; narrative assistance unavailable.",
            fixture_client=fixture_client,
        )

    memo = draft_decision_memo(evidence_context=evidence_context, client=recorder)
    if isinstance(memo, ErrorEnvelope):
        return _workflow_result(
            status=GptWorkflowStatus.NARRATIVE_UNAVAILABLE,
            contract=contract,
            memo=None,
            audit=None,
            audit_trail=recorder.responses,
            failure_stage=GptTask.DECISION_MEMO,
            message="Deterministic audit complete; narrative assistance unavailable.",
            fixture_client=fixture_client,
        )

    audit = audit_memo_claims(memo=memo, evidence_context=evidence_context, client=recorder)
    if isinstance(audit, ErrorEnvelope):
        return _workflow_result(
            status=GptWorkflowStatus.NARRATIVE_UNAVAILABLE,
            contract=contract,
            memo=memo,
            audit=None,
            audit_trail=recorder.responses,
            failure_stage=GptTask.CLAIM_AUDITOR,
            message="Deterministic audit complete; narrative assistance unavailable.",
            fixture_client=fixture_client,
        )
    trail = recorder.responses
    if audit.response.status is not GptCallStatus.SUCCESS:
        status = GptWorkflowStatus.NARRATIVE_UNAVAILABLE
        failure_stage = GptTask.CLAIM_AUDITOR
        message = "Deterministic audit complete; narrative assistance unavailable."
    elif audit.status is ClaimAuditStatus.PASS:
        status = GptWorkflowStatus.COMPLETED
        failure_stage = None
        message = "Deterministic audit complete; evidence-linked narrative passed claim audit."
    elif audit.status is ClaimAuditStatus.REVISE:
        status = GptWorkflowStatus.REVISE
        failure_stage = GptTask.CLAIM_AUDITOR
        message = "Deterministic audit complete; narrative claims require revision."
    else:
        status = GptWorkflowStatus.BLOCKED
        failure_stage = GptTask.CLAIM_AUDITOR
        message = "Deterministic audit complete; narrative claim release is blocked."
    return _workflow_result(
        status=status,
        contract=contract,
        memo=memo,
        audit=audit,
        audit_trail=trail,
        failure_stage=failure_stage,
        message=message,
        fixture_client=fixture_client,
    )


def build_fixture_gpt_client() -> FixtureStructuredGptClient:
    """Return the fixed deterministic, non-live transport used by tests and smoke runs."""

    return FixtureStructuredGptClient(
        {
            GptTask.CONTRACT_ASSISTANT: _contract_fixture,
            GptTask.DECISION_MEMO: _memo_fixture,
            GptTask.CLAIM_AUDITOR: _claim_fixture,
        }
    )


def _workflow_result(
    *,
    status: GptWorkflowStatus,
    contract: ContractSuggestion | None,
    memo: DecisionMemo | None,
    audit: ClaimAuditResult | None,
    audit_trail: tuple[GptResponseMetadata, ...],
    failure_stage: GptTask | None,
    message: str,
    fixture_client: bool,
) -> GptWorkflowResult:
    execution_modes = {item.execution_mode for item in audit_trail}
    fixture_non_live = fixture_client or (
        bool(audit_trail) and execution_modes == {GptExecutionMode.FIXTURE}
    )
    if audit is not None:
        references = audit.referenced_evidence_ids
    elif memo is not None:
        references = tuple(
            evidence_id for finding in memo.findings for evidence_id in finding.evidence_ids
        )
    else:
        references = ()
    value: dict[str, object] = {
        "artifact_version": ARTIFACT_VERSION,
        "workflow_version": "gpt-interpretation-workflow.v1",
        "prompt_versions": PROMPT_VERSIONS,
        "requested_model": DEFAULT_GPT_MODEL,
        "status": status,
        "fixture_non_live": fixture_non_live,
        "deterministic_analysis_available": True,
        "contract_suggestion": contract,
        "decision_memo": memo,
        "claim_audit": audit,
        "audit_trail": audit_trail,
        "referenced_evidence_ids": _ordered_unique(references),
        "user_message": message,
        "failure_stage": failure_stage,
        "normalized_output_sha256": "0" * 64,
    }
    provisional = GptWorkflowResult.model_validate(value)
    payload = provisional.to_canonical_dict()
    payload.pop("normalized_output_sha256", None)
    value["normalized_output_sha256"] = payload_sha256(payload)
    return GptWorkflowResult.model_validate(value)


def _contract_fixture(
    payload: Mapping[str, object],
    output_model: type[CanonicalModel],
) -> CanonicalModel:
    del output_model
    raw_profile = payload.get("dataset_profile")
    if not isinstance(raw_profile, Mapping):
        raise ValueError("fixture requires the safe profile object")
    columns_value = raw_profile.get("columns")
    hints_value = raw_profile.get("semantic_hints")
    if not isinstance(columns_value, (tuple, list)) or not isinstance(hints_value, (tuple, list)):
        raise ValueError("fixture requires bounded profile columns and hints")
    columns = tuple(
        str(column["name"])
        for column in columns_value
        if isinstance(column, Mapping) and isinstance(column.get("name"), str)
    )
    hints: dict[str, tuple[str, float]] = {}
    for hint in hints_value:
        if not isinstance(hint, Mapping):
            continue
        role = hint.get("semantic_role")
        column = hint.get("column")
        confidence = hint.get("confidence")
        if (
            isinstance(role, str)
            and isinstance(column, str)
            and column in columns
            and isinstance(confidence, (int, float))
            and not isinstance(confidence, bool)
            and role not in hints
        ):
            hints[role] = (column, float(confidence))
    suggestions: list[dict[str, object]] = []
    missing: list[str] = []
    for role in ContractRole:
        candidate = hints.get(role.value)
        column = candidate[0] if candidate is not None else None
        confidence = candidate[1] if candidate is not None else 0.0
        if role in {ContractRole.QUANTITY, ContractRole.DEPLOYMENT_GROUP} and column is None:
            missing.append(f"Confirm the required {role.value} column.")
        suggestions.append(
            {
                "role": role.value,
                "column": column,
                "confidence": confidence,
                "reason": (
                    "Matches a supplied deterministic semantic hint."
                    if column is not None
                    else "The safe profile does not explicitly support this role."
                ),
            }
        )
    return ContractSuggestionBody.model_validate(
        {
            "role_suggestions": suggestions,
            "likely_measurement_unit": None,
            "unit_evidence": None,
            "missing_required_inputs": tuple(missing),
            "clarification_questions": (
                "Confirm the quantity and deployment-group mappings.",
                "Provide the measurement unit and policy values through the structured form.",
            ),
            "requires_human_confirmation": True,
            "analysis_permitted": False,
        }
    )


def _memo_fixture(
    payload: Mapping[str, object],
    output_model: type[CanonicalModel],
) -> CanonicalModel:
    del output_model
    raw_context = payload.get("evidence_context")
    if not isinstance(raw_context, Mapping):
        raise ValueError("fixture requires one evidence context")
    context = EvidenceContext.model_validate(dict(raw_context))
    facts = {fact.fact_key: fact for fact in context.facts}
    pilot_min = facts.get("action.pilot_min")
    pilot_max = facts.get("action.pilot_max")
    interval = (
        f"{pilot_min.display_value.split()[0]}–{pilot_max.display_value.split()[0]} "
        f"{pilot_max.unit}"
        if pilot_min is not None and pilot_max is not None
        else None
    )
    state = context.action_state
    sections: dict[str, object]
    if state is ActionState.PILOT_RANGE_SUPPORTED and interval is not None:
        sections = {
            "title": "Supported controlled-pilot screening memo",
            "decision_snapshot": f"The accepted {state.value} action retains {interval}.",
            "what_the_evidence_shows": (
                "The recorded headroom and gate facts support a bounded pilot reference."
            ),
            "why_protocol_choice_matters": (
                "The protocol conflict flag is false for this recorded synthetic scenario."
            ),
            "recommended_next_step": (
                f"Treat {interval} as a retrospective screening reference for a controlled "
                "pilot and engineering review; it is not a production setpoint."
            ),
            "findings": (
                _finding(
                    "FND-001",
                    f"The accepted pilot range is {interval} and is not a production setpoint.",
                    ("action.state", "action.pilot_min", "action.pilot_max"),
                    facts,
                    "high",
                ),
                _finding(
                    "FND-002",
                    "The protocol conflict flag is false in the recorded result.",
                    ("protocol.conflict",),
                    facts,
                    "medium",
                ),
            ),
        }
    elif state is ActionState.PILOT_ONLY_CONSERVATIVE and interval is not None:
        sections = {
            "title": "Conservative controlled-pilot screening memo",
            "decision_snapshot": f"The accepted {state.value} action retains {interval}.",
            "what_the_evidence_shows": (
                "The recorded result preserves a bounded interval while showing protocol conflict."
            ),
            "why_protocol_choice_matters": (
                "Protocol disagreement requires a conservative interpretation."
            ),
            "recommended_next_step": (
                f"Treat {interval} as a retrospective screening reference for a controlled "
                "pilot and engineering review; it is not a production setpoint."
            ),
            "findings": (
                _finding(
                    "FND-001",
                    f"The conservative pilot interval is {interval} and requires review.",
                    ("action.state", "action.pilot_min", "action.pilot_max"),
                    facts,
                    "high",
                ),
                _finding(
                    "FND-002",
                    "Protocol conflict remains visible and prevents an agreement claim.",
                    ("protocol.conflict",),
                    facts,
                    "high",
                ),
            ),
        }
    elif state is ActionState.DIAGNOSE_PROCESS_FIRST:
        sections = {
            "title": "Process-diagnosis decision memo",
            "decision_snapshot": (f"The accepted {state.value} action supports no pilot interval."),
            "what_the_evidence_shows": (
                "The ordered-stability evidence contains a material warning."
            ),
            "why_protocol_choice_matters": (
                "Process instability is decisive even though other evidence is available."
            ),
            "recommended_next_step": (
                "Prioritize process diagnosis; no pilot interval is supported."
            ),
            "findings": (
                _finding(
                    "FND-001",
                    "Process diagnosis is required before any pilot interval can be considered.",
                    ("action.state", "gate.G1.status"),
                    facts,
                    "high",
                ),
            ),
        }
    else:
        sections = _other_action_fixture(state, facts)
    return DecisionMemoBody.model_validate(
        {
            **sections,
            "limitations": context.limitations,
        }
    )


def _other_action_fixture(
    state: ActionState,
    facts: Mapping[str, object],
) -> dict[str, object]:
    if state is ActionState.INSUFFICIENT_EVIDENCE:
        snapshot = "The current evidence cannot support an action."
        recommendation = "Collect sufficient evidence; diagnostic headroom is not an action."
    elif state is ActionState.NO_ACTIONABLE_HEADROOM:
        snapshot = "The accepted result has no actionable headroom and no pilot interval."
        recommendation = "Do not create a pilot interval; review the deterministic evidence."
    else:
        snapshot = "The contract is invalid, so no deterministic action is available."
        recommendation = "Correct and confirm the contract before analysis."
    return {
        "title": "Bounded deterministic decision memo",
        "decision_snapshot": snapshot,
        "what_the_evidence_shows": snapshot,
        "why_protocol_choice_matters": "No protocol can override the accepted action gate.",
        "recommended_next_step": recommendation,
        "findings": (
            _finding(
                "FND-001",
                snapshot,
                ("action.state",),
                facts,
                "high",
            ),
        ),
    }


def _finding(
    finding_id: str,
    statement: str,
    fact_keys: tuple[str, ...],
    facts: Mapping[str, object],
    importance: str,
) -> dict[str, object]:
    evidence: list[str] = []
    for key in fact_keys:
        fact = facts.get(key)
        if fact is None:
            raise ValueError("fixture fact is unavailable")
        for evidence_id in getattr(fact, "evidence_ids"):
            if evidence_id not in evidence:
                evidence.append(evidence_id)
    return {
        "finding_id": finding_id,
        "statement": statement,
        "evidence_ids": tuple(evidence),
        "fact_keys": fact_keys,
        "importance": importance,
    }


def _claim_fixture(
    payload: Mapping[str, object],
    output_model: type[CanonicalModel],
) -> CanonicalModel:
    del output_model
    claims = payload.get("claims")
    if not isinstance(claims, (tuple, list)):
        raise ValueError("fixture requires bounded claims")
    reviews: list[dict[str, object]] = []
    for claim in claims:
        if not isinstance(claim, Mapping):
            raise ValueError("fixture claim must be an object")
        reviews.append(
            {
                "claim_id": claim.get("claim_id"),
                "claim_text": claim.get("claim_text"),
                "verdict": "supported",
                "evidence_ids": claim.get("evidence_ids"),
                "fact_keys": claim.get("fact_keys"),
                "reason": "The fixture found no stronger claim-boundary classification.",
                "suggested_revision": None,
            }
        )
    return ClaimAuditBody.model_validate({"reviews": reviews})


def _ordered_unique(values: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        if value not in result:
            result.append(value)
    return tuple(result)


__all__ = ["build_fixture_gpt_client", "run_gpt_interpretation_workflow"]
