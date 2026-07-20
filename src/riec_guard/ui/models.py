"""Immutable display-only models for the public Streamlit product boundary."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class UiScenarioDefinition:
    """Allowlisted public scenario copy with no filesystem locator."""

    scenario_id: str
    scenario_version: str
    display_name: str
    mechanism_description: str
    domain_hint: str
    classification: str
    limitation: str


@dataclass(frozen=True, slots=True)
class UiDecisionSnapshot:
    """One deterministic action projection suitable for headline display."""

    action_state: str
    action_label: str
    decisive_reason: str
    pilot_min: float | None
    pilot_max: float | None
    unit: str
    protocol_conflict: bool
    conflict_summary: str
    protocol_spread: float | None

    @property
    def has_pilot_interval(self) -> bool:
        return self.pilot_min is not None and self.pilot_max is not None


@dataclass(frozen=True, slots=True)
class UiProtocolRow:
    """Small protocol display row; never a canonical artifact dump."""

    protocol_id: str
    name: str
    status: str
    value: float | None
    lower_bound: float | None
    unit: str | None
    role_limitation: str


@dataclass(frozen=True, slots=True)
class UiGateStatus:
    """Allowlisted gate outcome and public interpretation."""

    gate_id: str
    status: str
    supports_action: bool
    detail: str


@dataclass(frozen=True, slots=True)
class UiEvidenceNode:
    """Aggregate provenance node with no row-level evidence."""

    component: str
    evidence_id: str
    content_sha256: str
    parent_evidence_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UiScenarioBundle:
    """Complete immutable public display bundle for one verified scenario."""

    definition: UiScenarioDefinition
    result_source: str
    source_explanation: str
    dataset_sha256: str
    catalog_sha256: str
    summary_sha256: str
    contract_id: str
    policy_profile_id: str
    row_count: int
    deployment_group_count: int
    product_count: int
    rows_per_product: int
    nominal_quantity: float
    lower_limit: float
    alpha: float
    measurement_resolution: float
    minimum_actionable_shift: float
    maximum_screening_shift: float
    protocol_spread_tolerance: float
    bootstrap_replicates: int
    bootstrap_seed: int
    riec_winner: str
    riec_runner_up: str | None
    riec_near_tie: bool
    equivalence_set: tuple[str, ...]
    decision: UiDecisionSnapshot
    protocols: tuple[UiProtocolRow, ...]
    gates: tuple[UiGateStatus, ...]
    bootstrap_requested: int
    bootstrap_successful: int
    bootstrap_failed: int
    evidence_nodes: tuple[UiEvidenceNode, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UiGptCapability:
    """One short product statement about the bounded GPT layer."""

    title: str
    description: str


@dataclass(frozen=True, slots=True)
class UiGptRoleSuggestion:
    """Advisory contract-role suggestion projected from the GPT artifact."""

    role: str
    column: str | None
    confidence: float
    reason: str


@dataclass(frozen=True, slots=True)
class UiGptFinding:
    """Evidence-linked memo finding projected for display and download."""

    finding_id: str
    statement: str
    evidence_ids: tuple[str, ...]
    fact_keys: tuple[str, ...]
    importance: str


@dataclass(frozen=True, slots=True)
class UiClaimReview:
    """Merged claim-review row with deterministic precedence already applied."""

    claim_id: str
    verdict: str
    reason: str
    evidence_ids: tuple[str, ...]
    fact_keys: tuple[str, ...]
    suggested_revision: str | None


@dataclass(frozen=True, slots=True)
class UiGptCall:
    """Safe transport metadata; prompts and request payloads are deliberately absent."""

    task: str
    status: str
    execution_mode: str
    requested_model: str
    returned_model: str | None
    prompt_version: str
    response_id: str | None
    input_sha256: str
    output_sha256: str | None
    attempt_count: int
    input_tokens: int | None
    output_tokens: int | None
    total_tokens: int | None
    error_code: str | None


@dataclass(frozen=True, slots=True)
class UiGptResult:
    """Allowlisted GPT workflow projection held only in Streamlit session state."""

    scenario_id: str
    context_source: str
    mode_label: str
    status: str
    user_message: str
    fixture_non_live: bool
    deterministic_analysis_available: bool
    requested_model: str
    prompt_versions: tuple[str, ...]
    workflow_sha256: str
    contract_suggestions: tuple[UiGptRoleSuggestion, ...]
    requires_human_confirmation: bool | None
    analysis_permitted: bool | None
    memo_title: str | None
    decision_snapshot: str | None
    evidence_summary: str | None
    protocol_explanation: str | None
    recommended_next_step: str | None
    memo_limitations: tuple[str, ...]
    findings: tuple[UiGptFinding, ...]
    claim_audit_status: str | None
    deterministic_validation_status: str | None
    claim_reviews: tuple[UiClaimReview, ...]
    referenced_evidence_ids: tuple[str, ...]
    calls: tuple[UiGptCall, ...]


@dataclass(frozen=True, slots=True)
class UiDownloadPacket:
    """In-memory deterministic JSON download."""

    filename: str
    media_type: str
    content: bytes
    content_sha256: str
