"""Immutable typed artifacts for the bounded GPT interpretation layer."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Annotated, Generic, Literal, TypeVar

from pydantic import Field, StringConstraints, model_validator

from riec_guard.contract.models import ActionState, ColumnDataType, SemanticRole
from riec_guard.errors import (
    CanonicalModel,
    ErrorClass,
    ErrorEnvelope,
    ErrorStage,
    FiniteNumber,
    ImmutableTuple,
    LimitedString32,
    LimitedString50,
    LimitedString100,
    LimitedString128,
    LimitedString200,
    LimitedString300,
    LimitedString500,
    LimitedString1000,
    StrictStrEnum,
    UniqueTuple,
)

Sha256 = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
EvidenceId = Annotated[
    str,
    StringConstraints(pattern=r"^EV-[A-Z0-9_]{2,16}-[A-F0-9]{12}$"),
]
FactKey = Annotated[str, StringConstraints(pattern=r"^[a-z][a-zA-Z0-9_.]{2,99}$")]
FindingId = Annotated[str, StringConstraints(pattern=r"^FND-[0-9]{3}$")]
ClaimId = Annotated[str, StringConstraints(pattern=r"^CLM-[0-9]{3}$")]
PromptVersion = Annotated[
    str,
    StringConstraints(pattern=r"^(contract-assistant|decision-memo|claim-auditor)\.v1$"),
]

ARTIFACT_VERSION = "1.0.0"
DEFAULT_GPT_MODEL = "gpt-5.6"
CONTRACT_PROMPT_VERSION = "contract-assistant.v1"
MEMO_PROMPT_VERSION = "decision-memo.v1"
CLAIM_PROMPT_VERSION = "claim-auditor.v1"
PROMPT_VERSIONS = (
    CONTRACT_PROMPT_VERSION,
    MEMO_PROMPT_VERSION,
    CLAIM_PROMPT_VERSION,
)


class GptTask(StrictStrEnum):
    CONTRACT_ASSISTANT = "contract_assistant"
    DECISION_MEMO = "decision_memo"
    CLAIM_AUDITOR = "claim_auditor"


class GptCallStatus(StrictStrEnum):
    SUCCESS = "success"
    REFUSED = "refused"
    INCOMPLETE = "incomplete"
    ERROR = "error"


class GptExecutionMode(StrictStrEnum):
    LIVE = "live"
    FIXTURE = "fixture"
    NOT_EXECUTED = "not_executed"


class FixtureFailureMode(StrictStrEnum):
    NONE = "none"
    REFUSAL = "refusal"
    INCOMPLETE = "incomplete"
    MALFORMED = "malformed"
    TIMEOUT = "timeout"
    AUTHENTICATION = "authentication"
    ACCESS = "access"


class GptWorkflowStatus(StrictStrEnum):
    COMPLETED = "completed"
    REVISE = "revise"
    BLOCKED = "blocked"
    NARRATIVE_UNAVAILABLE = "narrative_unavailable"


class ClaimVerdict(StrictStrEnum):
    SUPPORTED = "supported"
    SUPPORTED_WITH_QUALIFICATION = "supported_with_qualification"
    UNSUPPORTED = "unsupported"
    OVERSTATED = "overstated"
    PROHIBITED = "prohibited"
    NOT_A_CLAIM = "not_a_claim"


class ClaimAuditStatus(StrictStrEnum):
    PASS = "pass"
    REVISE = "revise"
    BLOCKED = "blocked"


class FactType(StrictStrEnum):
    PROFILE = "profile"
    POLICY = "policy"
    SELECTION = "selection"
    PROTOCOL = "protocol"
    GATE = "gate"
    ACTION = "action"
    LIMITATION = "limitation"


class FindingImportance(StrictStrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class GptTokenUsage(CanonicalModel):
    input_tokens: Annotated[int, Field(ge=0, le=10_000_000)] | None
    output_tokens: Annotated[int, Field(ge=0, le=10_000_000)] | None
    total_tokens: Annotated[int, Field(ge=0, le=20_000_000)] | None


class GptRequestMetadata(CanonicalModel):
    artifact_version: Literal["1.0.0"]
    task: GptTask
    prompt_version: PromptVersion
    requested_model: Literal["gpt-5.6"]
    sanitized_input_sha256: Sha256
    serialized_payload_bytes: Annotated[int, Field(ge=2, le=65_536)]
    execution_mode: GptExecutionMode


class GptResponseMetadata(CanonicalModel):
    artifact_version: Literal["1.0.0"]
    task: GptTask
    prompt_version: PromptVersion
    requested_model: Literal["gpt-5.6"]
    returned_model: LimitedString100 | None
    response_id: LimitedString200 | None
    sanitized_input_sha256: Sha256
    normalized_output_sha256: Sha256 | None
    status: GptCallStatus
    refusal: bool
    incomplete: bool
    usage: GptTokenUsage
    attempt_count: Annotated[int, Field(ge=0, le=2)]
    execution_mode: GptExecutionMode
    error_code: LimitedString100 | None

    @model_validator(mode="after")
    def _validate_status_flags(self) -> GptResponseMetadata:
        if self.status is GptCallStatus.SUCCESS:
            if self.normalized_output_sha256 is None or self.refusal or self.incomplete:
                raise ValueError("successful GPT metadata requires a complete output hash")
        elif self.normalized_output_sha256 is not None:
            raise ValueError("non-success GPT metadata cannot contain an output hash")
        if self.refusal != (self.status is GptCallStatus.REFUSED):
            raise ValueError("refusal flag and status are inconsistent")
        if self.incomplete != (self.status is GptCallStatus.INCOMPLETE):
            raise ValueError("incomplete flag and status are inconsistent")
        return self


class SafeColumnMetadata(CanonicalModel):
    name: LimitedString128
    dtype: ColumnDataType
    missing_fraction: Annotated[FiniteNumber, Field(ge=0, le=1)]
    unique_count: Annotated[int, Field(ge=0, le=100_000)]


class SafeSemanticHint(CanonicalModel):
    semantic_role: SemanticRole
    column: LimitedString128 | None
    confidence: Annotated[FiniteNumber, Field(ge=0, le=1)]
    reasons: Annotated[ImmutableTuple[LimitedString300], Field(max_length=5)]


class SafeDatasetProfilePayload(CanonicalModel):
    artifact_version: Literal["1.0.0"]
    payload_version: Literal["safe-dataset-profile.v1"]
    dataset_id: LimitedString128
    dataset_sha256: Sha256
    row_count: Annotated[int, Field(ge=1, le=100_000)]
    columns: Annotated[ImmutableTuple[SafeColumnMetadata], Field(min_length=1, max_length=100)]
    semantic_hints: Annotated[ImmutableTuple[SafeSemanticHint], Field(max_length=100)]
    raw_rows_included: Literal[False]
    cell_values_included: Literal[False]
    direct_identifiers_included: Literal[False]
    local_paths_included: Literal[False]
    payload_sha256: Sha256


class ContractRole(StrictStrEnum):
    QUANTITY = "quantity"
    PRODUCT = "product"
    DEPLOYMENT_GROUP = "deployment_group"
    TIME = "time"
    STREAM = "stream"
    SHIFT = "shift"


class ContractRoleSuggestion(CanonicalModel):
    role: ContractRole
    column: LimitedString128 | None
    confidence: Annotated[FiniteNumber, Field(ge=0, le=1)]
    reason: LimitedString300


class ContractSuggestionBody(CanonicalModel):
    role_suggestions: Annotated[
        ImmutableTuple[ContractRoleSuggestion], Field(min_length=1, max_length=6)
    ]
    likely_measurement_unit: LimitedString32 | None
    unit_evidence: LimitedString300 | None
    missing_required_inputs: Annotated[UniqueTuple[LimitedString200], Field(max_length=12)]
    clarification_questions: Annotated[UniqueTuple[LimitedString300], Field(max_length=8)]
    requires_human_confirmation: Literal[True]
    analysis_permitted: Literal[False]


class ContractSuggestion(CanonicalModel):
    artifact_version: Literal["1.0.0"]
    prompt_version: Literal["contract-assistant.v1"]
    request: GptRequestMetadata
    response: GptResponseMetadata
    role_suggestions: Annotated[
        ImmutableTuple[ContractRoleSuggestion], Field(min_length=1, max_length=6)
    ]
    likely_measurement_unit: LimitedString32 | None
    unit_evidence: LimitedString300 | None
    missing_required_inputs: Annotated[UniqueTuple[LimitedString200], Field(max_length=12)]
    clarification_questions: Annotated[UniqueTuple[LimitedString300], Field(max_length=8)]
    requires_human_confirmation: Literal[True]
    analysis_permitted: Literal[False]


class EvidenceFact(CanonicalModel):
    fact_key: FactKey
    display_value: LimitedString200
    unit: LimitedString32 | None
    evidence_ids: Annotated[UniqueTuple[EvidenceId], Field(min_length=1, max_length=8)]
    fact_type: FactType


class EvidenceDescriptor(CanonicalModel):
    evidence_id: EvidenceId
    component: Annotated[str, StringConstraints(pattern=r"^(RIEC|PROTOCOL|ACTION)$")]
    description: LimitedString300


class EvidenceContext(CanonicalModel):
    artifact_version: Literal["1.0.0"]
    context_version: Literal["evidence-context.v1"]
    context_id: Annotated[str, StringConstraints(pattern=r"^CTX-[A-F0-9]{12}$")]
    scenario_id: LimitedString100 | None
    dataset_sha256: Sha256
    contract_id: Annotated[str, StringConstraints(pattern=r"^AC-[A-F0-9]{12}$")]
    action_state: ActionState
    facts: Annotated[ImmutableTuple[EvidenceFact], Field(min_length=1, max_length=50)]
    evidence_descriptors: Annotated[
        ImmutableTuple[EvidenceDescriptor], Field(min_length=1, max_length=32)
    ]
    valid_evidence_ids: Annotated[UniqueTuple[EvidenceId], Field(min_length=1, max_length=32)]
    valid_numeric_tokens: Annotated[UniqueTuple[LimitedString50], Field(max_length=100)]
    valid_action_labels: Annotated[UniqueTuple[LimitedString50], Field(min_length=1, max_length=6)]
    valid_units: Annotated[UniqueTuple[LimitedString32], Field(max_length=12)]
    limitations: Annotated[UniqueTuple[LimitedString500], Field(min_length=4, max_length=12)]
    payload_sha256: Sha256


class MemoFinding(CanonicalModel):
    finding_id: FindingId
    statement: LimitedString500
    evidence_ids: Annotated[UniqueTuple[EvidenceId], Field(min_length=1, max_length=8)]
    fact_keys: Annotated[UniqueTuple[FactKey], Field(min_length=1, max_length=12)]
    importance: FindingImportance


class DecisionMemoBody(CanonicalModel):
    title: LimitedString200
    decision_snapshot: LimitedString500
    what_the_evidence_shows: LimitedString1000
    why_protocol_choice_matters: LimitedString1000
    recommended_next_step: LimitedString1000
    limitations: Annotated[UniqueTuple[LimitedString500], Field(min_length=4, max_length=12)]
    findings: Annotated[ImmutableTuple[MemoFinding], Field(min_length=1, max_length=12)]


class DecisionMemo(CanonicalModel):
    artifact_version: Literal["1.0.0"]
    prompt_version: Literal["decision-memo.v1"]
    action_state: ActionState
    evidence_context_sha256: Sha256
    request: GptRequestMetadata
    response: GptResponseMetadata
    title: LimitedString200
    decision_snapshot: LimitedString500
    what_the_evidence_shows: LimitedString1000
    why_protocol_choice_matters: LimitedString1000
    recommended_next_step: LimitedString1000
    limitations: Annotated[UniqueTuple[LimitedString500], Field(min_length=4, max_length=12)]
    findings: Annotated[ImmutableTuple[MemoFinding], Field(min_length=1, max_length=12)]


class ClaimReview(CanonicalModel):
    claim_id: ClaimId
    claim_text: LimitedString1000
    verdict: ClaimVerdict
    evidence_ids: Annotated[UniqueTuple[EvidenceId], Field(max_length=8)]
    fact_keys: Annotated[UniqueTuple[FactKey], Field(max_length=12)]
    reason: LimitedString500
    suggested_revision: LimitedString1000 | None


class ClaimAuditBody(CanonicalModel):
    reviews: Annotated[ImmutableTuple[ClaimReview], Field(min_length=1, max_length=20)]


class ClaimAuditResult(CanonicalModel):
    artifact_version: Literal["1.0.0"]
    prompt_version: Literal["claim-auditor.v1"]
    memo_sha256: Sha256
    evidence_context_sha256: Sha256
    request: GptRequestMetadata
    response: GptResponseMetadata
    status: ClaimAuditStatus
    deterministic_validation_status: Literal["passed", "blocked"]
    deterministic_reviews: Annotated[ImmutableTuple[ClaimReview], Field(max_length=20)]
    model_reviews: Annotated[ImmutableTuple[ClaimReview], Field(max_length=20)]
    reviews: Annotated[ImmutableTuple[ClaimReview], Field(min_length=1, max_length=20)]
    referenced_evidence_ids: Annotated[UniqueTuple[EvidenceId], Field(max_length=32)]
    failure_reason: LimitedString500 | None


class GptWorkflowResult(CanonicalModel):
    artifact_version: Literal["1.0.0"]
    workflow_version: Literal["gpt-interpretation-workflow.v1"]
    prompt_versions: Annotated[ImmutableTuple[PromptVersion], Field(min_length=3, max_length=3)]
    requested_model: Literal["gpt-5.6"]
    status: GptWorkflowStatus
    fixture_non_live: bool
    deterministic_analysis_available: Literal[True]
    contract_suggestion: ContractSuggestion | None
    decision_memo: DecisionMemo | None
    claim_audit: ClaimAuditResult | None
    audit_trail: Annotated[ImmutableTuple[GptResponseMetadata], Field(max_length=3)]
    referenced_evidence_ids: Annotated[UniqueTuple[EvidenceId], Field(max_length=32)]
    user_message: LimitedString500
    failure_stage: GptTask | None
    normalized_output_sha256: Sha256


OutputT = TypeVar("OutputT", bound=CanonicalModel)


@dataclass(frozen=True, slots=True)
class StructuredGptResponse(Generic[OutputT]):
    """Transport-neutral typed response; raw prompts and SDK objects never escape."""

    output: OutputT | None
    request: GptRequestMetadata
    metadata: GptResponseMetadata


def gpt_error(
    code: str,
    message: str,
    *,
    error_class: ErrorClass,
    recoverable: bool,
    user_action: str,
    safe_details: dict[str, object] | None = None,
) -> ErrorEnvelope:
    """Build one sanitized GPT-stage failure without exception text or local state."""

    digest = hashlib.sha256(f"{code}\0{message}".encode()).hexdigest()[:12].upper()
    return ErrorEnvelope.model_validate(
        {
            "schema_version": "1.0.0",
            "error_id": f"ERR-{digest}",
            "stage": ErrorStage.GPT,
            "error_class": error_class,
            "code": code,
            "message": message,
            "recoverable": recoverable,
            "user_action": user_action,
            "safe_details": safe_details or {},
            "cause_chain": (),
        }
    )


__all__ = [
    "ARTIFACT_VERSION",
    "CLAIM_PROMPT_VERSION",
    "CONTRACT_PROMPT_VERSION",
    "DEFAULT_GPT_MODEL",
    "MEMO_PROMPT_VERSION",
    "PROMPT_VERSIONS",
    "ClaimAuditBody",
    "ClaimAuditResult",
    "ClaimAuditStatus",
    "ClaimReview",
    "ClaimVerdict",
    "ContractRole",
    "ContractRoleSuggestion",
    "ContractSuggestion",
    "ContractSuggestionBody",
    "DecisionMemo",
    "DecisionMemoBody",
    "EvidenceContext",
    "EvidenceDescriptor",
    "EvidenceFact",
    "FactType",
    "FindingImportance",
    "FixtureFailureMode",
    "GptCallStatus",
    "GptExecutionMode",
    "GptRequestMetadata",
    "GptResponseMetadata",
    "GptTask",
    "GptTokenUsage",
    "GptWorkflowResult",
    "GptWorkflowStatus",
    "MemoFinding",
    "OutputT",
    "SafeColumnMetadata",
    "SafeDatasetProfilePayload",
    "SafeSemanticHint",
    "StructuredGptResponse",
    "gpt_error",
]
