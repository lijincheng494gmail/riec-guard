from __future__ import annotations

from types import MappingProxyType
from typing import Annotated, ClassVar, Literal, TypeAlias, cast

from pydantic import Field, StringConstraints

from riec_guard.errors import (
    CanonicalModel,
    ErrorEnvelope,
    FiniteNumber,
    ImmutableTuple,
    JsonValue,
    LimitedString32,
    LimitedString100,
    LimitedString128,
    LimitedString200,
    LimitedString300,
    LimitedString500,
    LimitedString1000,
    LimitedString2000,
    LimitedString3000,
    StrictStrEnum,
    UniqueTuple,
    optional_field,
)
from riec_guard.evidence.models import EvidenceLedger
from riec_guard.telemetry.models import RunManifest

RunId: TypeAlias = Annotated[str, StringConstraints(pattern=r"^RUN-[A-F0-9]{12}$")]
ContractId: TypeAlias = Annotated[str, StringConstraints(pattern=r"^AC-[A-F0-9]{12}$")]
EvidenceId: TypeAlias = Annotated[
    str, StringConstraints(pattern=r"^EV-[A-Z0-9_]{2,16}-[A-F0-9]{12}$")
]
Sha256: TypeAlias = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
SemanticVersion: TypeAlias = Annotated[str, StringConstraints(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]
DatasetId: TypeAlias = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{2,127}$")]
CandidateId: TypeAlias = Annotated[str, StringConstraints(pattern=r"^M[0-9]+_[a-z0-9_]+$")]
ReasonCode: TypeAlias = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")]
ClaimId: TypeAlias = Annotated[str, StringConstraints(pattern=r"^CLM-[0-9]{3}$")]


class CompilerMode(StrictStrEnum):
    GPT_STRUCTURED_OUTPUT = "gpt_structured_output"
    MANUAL_FORM = "manual_form"
    VERSIONED_BUILTIN = "versioned_builtin"


class SourceMode(StrictStrEnum):
    BUILTIN_SYNTHETIC = "builtin_synthetic"
    UPLOADED_PUBLIC = "uploaded_public"
    LOCAL_PRIVATE = "local_private"


class SourceEncoding(StrictStrEnum):
    UTF8 = "utf-8"
    UTF8_SIG = "utf-8-sig"
    INTERNAL = "internal"


class SyntheticMechanism(StrictStrEnum):
    STABLE_SYMMETRIC = "stable_symmetric"
    LEFT_SKEW_FOAMING = "left_skew_foaming"
    HEAVY_TAIL_PARTICULATE = "heavy_tail_particulate"
    MULTIMODAL_STREAMS = "multimodal_streams"
    BATCH_DRIFT_CHANGE_POINT = "batch_drift_change_point"
    AUTOCORRELATED_VISCOUS = "autocorrelated_viscous"
    DENSITY_TARE_MEASUREMENT_UNCERTAINTY = "density_tare_measurement_uncertainty"


class QuantitySemantics(StrictStrEnum):
    NET_CONTENT = "net_content"
    GROSS_WEIGHT = "gross_weight"
    NET_WEIGHT = "net_weight"
    VOLUME = "volume"
    MASS = "mass"
    OTHER = "other"


class ConversionMethod(StrictStrEnum):
    NONE = "none"
    FIXED_DENSITY = "fixed_density"
    ROW_DENSITY = "row_density"
    GROSS_MINUS_TARE = "gross_minus_tare"
    CUSTOM = "custom"


class OrderingStatus(StrictStrEnum):
    CONFIRMED = "confirmed"
    UNAVAILABLE = "unavailable"
    AMBIGUOUS = "ambiguous"


class PolicySourceKind(StrictStrEnum):
    STRUCTURED_FORM = "structured_form"
    PASTED_TEXT = "pasted_text"
    TEXT_FILE = "text_file"
    BUILTIN_PROFILE = "builtin_profile"


class PrivacyClassification(StrictStrEnum):
    PUBLIC_SYNTHETIC = "public_synthetic"
    PUBLIC_USER_UPLOAD = "public_user_upload"
    PRIVATE_INDUSTRIAL = "private_industrial"


class StorageMode(StrictStrEnum):
    EPHEMERAL_PUBLIC_SESSION = "ephemeral_public_session"
    LOCAL_PRIVATE_WORKSPACE = "local_private_workspace"


class IssueSeverity(StrictStrEnum):
    BLOCKING = "blocking"
    WARNING = "warning"


class AssumptionSource(StrictStrEnum):
    USER = "user"
    BUILTIN_PROFILE = "builtin_profile"
    GPT_INFERENCE = "gpt_inference"
    DETERMINISTIC_INFERENCE = "deterministic_inference"


class ConfirmationStatus(StrictStrEnum):
    DRAFT = "draft"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class ConfirmedBy(StrictStrEnum):
    USER = "user"
    VERSIONED_BUILTIN = "versioned_builtin"
    NONE = "none"


class ContractCompiler(CanonicalModel):
    mode: CompilerMode
    model: LimitedString100 | None
    structured_output_schema_version: LimitedString32
    fallback_used: bool
    request_id: LimitedString200 | None = None


class ContractSource(CanonicalModel):
    mode: SourceMode
    dataset_id: DatasetId
    dataset_sha256: Sha256
    filename_display: Annotated[str, StringConstraints(max_length=255)] | None
    row_count: Annotated[int, Field(ge=1, le=100_000)]
    column_count: Annotated[int, Field(ge=1, le=100)]
    encoding: SourceEncoding = optional_field()
    synthetic_mechanism: SyntheticMechanism | None = None


class RequiredColumnRef(CanonicalModel):
    column: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    confidence: Annotated[FiniteNumber, Field(ge=0, le=1)]
    confirmed: bool


class OptionalColumnRef(CanonicalModel):
    column: LimitedString128 | None
    confidence: Annotated[FiniteNumber, Field(ge=0, le=1)]
    confirmed: bool


class ColumnMapping(CanonicalModel):
    quantity: RequiredColumnRef
    product: OptionalColumnRef
    deployment_group: RequiredColumnRef
    time: OptionalColumnRef
    stream: OptionalColumnRef
    shift: OptionalColumnRef
    weight: OptionalColumnRef = optional_field()
    density: OptionalColumnRef = optional_field()
    tare: OptionalColumnRef = optional_field()


class MeasurementConversion(CanonicalModel):
    required: bool
    method: ConversionMethod
    fixed_density: Annotated[FiniteNumber, Field(gt=0)] | None = None
    formula_note: LimitedString1000 | None = None


class Measurement(CanonicalModel):
    quantity_semantics: QuantitySemantics
    unit: Annotated[str, StringConstraints(pattern=r"^[A-Za-zµμ%][A-Za-z0-9µμ%./*^ _-]{0,31}$")]
    measurement_resolution: Annotated[FiniteNumber, Field(gt=0)] | None
    conversion: MeasurementConversion


class Grouping(CanonicalModel):
    deployment_unit_name: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    deployment_group_columns: Annotated[
        UniqueTuple[Annotated[str, StringConstraints(min_length=1, max_length=128)]],
        Field(min_length=1, max_length=4),
    ]
    nested_context_columns: Annotated[
        UniqueTuple[Annotated[str, StringConstraints(min_length=1, max_length=128)]],
        Field(max_length=8),
    ] = optional_field()
    no_random_row_fallback: Literal[True]


class Ordering(CanonicalModel):
    status: OrderingStatus
    time_column: LimitedString128 | None
    timezone: LimitedString100 | None
    within_stream_order_confirmed: bool
    tie_break_columns: Annotated[UniqueTuple[LimitedString128], Field(max_length=4)] = (
        optional_field()
    )


class PolicySource(CanonicalModel):
    kind: PolicySourceKind
    title: LimitedString200 | None
    text_sha256: Sha256 | None
    user_confirmed: bool


class AuditPolicy(CanonicalModel):
    nominal_quantity: FiniteNumber
    lower_limit: FiniteNumber
    underfill_event: Literal["adjusted_quantity_strictly_less_than_lower_limit"]
    alpha: Annotated[FiniteNumber, Field(gt=0, lt=0.5)]
    minimum_actionable_shift: Annotated[FiniteNumber, Field(ge=0)]
    maximum_screening_shift: Annotated[FiniteNumber, Field(gt=0)]
    protocol_spread_tolerance: Annotated[FiniteNumber, Field(ge=0)]
    policy_source: PolicySource
    notes: LimitedString2000 | None = None


class EvidenceProfile(CanonicalModel):
    profile_version: LimitedString32
    min_rows: Annotated[int, Field(ge=1)]
    min_groups_exploratory: Annotated[int, Field(ge=2)]
    min_groups_action: Annotated[int, Field(ge=2)]
    min_expected_tail_count: Annotated[FiniteNumber, Field(ge=1)]
    min_ordered_points_per_stream: Annotated[int, Field(ge=3)]
    min_ordered_coverage: Annotated[FiniteNumber, Field(ge=0, le=1)]
    bootstrap_replicates: Annotated[int, Field(ge=100, le=2000)]
    bootstrap_lower_confidence: Annotated[FiniteNumber, Field(gt=0.5, lt=1)]
    bootstrap_max_failure_fraction: Annotated[FiniteNumber, Field(ge=0, le=0.25)]


class RiecSettings(CanonicalModel):
    candidate_registry_id: DatasetId
    baseline_candidate_id: Literal["M0_intercept"]
    risk_aggregation: Literal["row_weighted_grouped_mse"]
    group_balanced_diagnostic: bool = optional_field()
    c: Annotated[FiniteNumber, Field(ge=0)]
    near_tie_abs_tol: Annotated[FiniteNumber, Field(ge=0)]
    near_tie_rel_tol: Annotated[FiniteNumber, Field(ge=0)]
    splitter: Literal["leave_one_deployment_group_out"]
    max_exact_logo_groups: Annotated[int, Field(ge=2, le=1000)]


class PrivacyBoundary(CanonicalModel):
    classification: PrivacyClassification
    raw_rows_to_gpt: Literal[False]
    direct_identifiers_to_gpt: Literal[False]
    storage_mode: StorageMode
    redacted_summary_allowed: bool = optional_field()


class UnresolvedField(CanonicalModel):
    field_path: LimitedString200
    severity: IssueSeverity
    question: LimitedString500


class ContractAssumption(CanonicalModel):
    assumption_id: Annotated[str, StringConstraints(pattern=r"^ASM-[0-9]{3}$")]
    text: LimitedString1000
    source: AssumptionSource
    user_confirmed: bool


class ContractConfirmation(CanonicalModel):
    status: ConfirmationStatus
    confirmed_fields: UniqueTuple[LimitedString200]
    confirmed_at: str | None
    confirmed_by: ConfirmedBy = optional_field()


class AuditContract(CanonicalModel):
    schema_logical_name = "audit_contract"

    schema_version: Literal["1.0.0"]
    contract_id: ContractId
    created_at: str | None = None
    compiler: ContractCompiler = optional_field()
    source: ContractSource
    column_mapping: ColumnMapping
    measurement: Measurement
    grouping: Grouping
    ordering: Ordering
    policy: AuditPolicy
    evidence_profile: EvidenceProfile
    riec: RiecSettings
    privacy: PrivacyBoundary
    unresolved_fields: Annotated[ImmutableTuple[UnresolvedField], Field(max_length=50)]
    assumptions: Annotated[ImmutableTuple[ContractAssumption], Field(max_length=100)] = (
        optional_field()
    )
    confirmation: ContractConfirmation


class ColumnDataType(StrictStrEnum):
    INTEGER = "integer"
    NUMBER = "number"
    STRING = "string"
    BOOLEAN = "boolean"
    DATETIME = "datetime"
    UNKNOWN = "unknown"


class SemanticRole(StrictStrEnum):
    QUANTITY = "quantity"
    PRODUCT = "product"
    DEPLOYMENT_GROUP = "deployment_group"
    TIME = "time"
    STREAM = "stream"
    SHIFT = "shift"
    WEIGHT = "weight"
    DENSITY = "density"
    TARE = "tare"


class NumericSummary(CanonicalModel):
    min: FiniteNumber
    median: FiniteNumber
    max: FiniteNumber


class ColumnProfile(CanonicalModel):
    name: LimitedString128
    dtype: ColumnDataType
    missing_fraction: Annotated[FiniteNumber, Field(ge=0, le=1)]
    unique_count: Annotated[int, Field(ge=0)]
    safe_examples: Annotated[ImmutableTuple[JsonValue], Field(max_length=3)]
    numeric_summary: NumericSummary | None = None


class CandidateSemanticMapping(CanonicalModel):
    semantic_role: SemanticRole
    column: LimitedString128 | None
    confidence: Annotated[FiniteNumber, Field(ge=0, le=1)]
    reasons: Annotated[ImmutableTuple[LimitedString300], Field(max_length=10)]


class PrivacyRedaction(CanonicalModel):
    raw_rows_included: Literal[False]
    direct_identifiers_included: Literal[False]
    high_cardinality_values_included: Literal[False]


class DatasetProfile(CanonicalModel):
    schema_logical_name = "dataset_profile"

    schema_version: Literal["1.0.0"]
    dataset_id: DatasetId
    dataset_sha256: Sha256
    row_count: Annotated[int, Field(ge=1, le=100_000)]
    column_profiles: Annotated[ImmutableTuple[ColumnProfile], Field(min_length=1, max_length=100)]
    candidate_semantic_mappings: Annotated[
        ImmutableTuple[CandidateSemanticMapping], Field(max_length=100)
    ]
    privacy_redaction: PrivacyRedaction


class ModelFamily(StrictStrEnum):
    OLS_FIXED_EFFECTS = "ols_fixed_effects"


class FormulaTerm(StrictStrEnum):
    INTERCEPT = "intercept"
    PRODUCT = "product"
    STREAM = "stream"
    SHIFT = "shift"
    TIME = "time"


class RequiredSemantic(StrictStrEnum):
    QUANTITY = "quantity"
    PRODUCT = "product"
    STREAM = "stream"
    SHIFT = "shift"
    TIME = "time"
    DEPLOYMENT_GROUP = "deployment_group"


class ParameterCountRule(CanonicalModel):
    kind: Literal["realized_design_rank"]
    include_intercept: bool


class FeasibilityRequirements(CanonicalModel):
    required_semantics: UniqueTuple[RequiredSemantic]
    min_rows: Annotated[int, Field(ge=1)]
    min_groups: Annotated[int, Field(ge=2)]
    full_rank_required: bool


class CandidateDefinition(CanonicalModel):
    candidate_id: CandidateId
    label: Annotated[str, StringConstraints(max_length=120)]
    model_family: ModelFamily
    formula_terms: Annotated[UniqueTuple[FormulaTerm], Field(max_length=12)]
    version: SemanticVersion
    parameter_count_rule: ParameterCountRule
    feasibility_requirements: FeasibilityRequirements
    enabled: bool
    notes: LimitedString1000 | None = None


class CandidateRegistry(CanonicalModel):
    schema_logical_name = "candidate_registry"

    schema_version: Literal["1.0.0"]
    registry_id: DatasetId
    registry_version: SemanticVersion
    frozen_before_ranking: Literal[True]
    baseline_candidate_id: Literal["M0_intercept"]
    description: LimitedString1000 = optional_field()
    candidates: Annotated[ImmutableTuple[CandidateDefinition], Field(min_length=1, max_length=32)]


class CandidateStatus(StrictStrEnum):
    OK = "ok"
    INFEASIBLE = "infeasible"
    FIT_FAILED = "fit_failed"
    PREDICTION_FAILED = "prediction_failed"


class SelectionDecisionStatus(StrictStrEnum):
    SELECTED = "selected"
    NEAR_TIE = "near_tie"
    NO_FEASIBLE_CANDIDATE = "no_feasible_candidate"


class CandidateLedgerEntry(CanonicalModel):
    candidate_id: CandidateId
    status: CandidateStatus
    parameter_count: Annotated[int, Field(ge=0)] | None
    bic_eff: FiniteNumber | None
    grouped_risk: Annotated[FiniteNumber, Field(ge=0)] | None
    group_balanced_risk: Annotated[FiniteNumber, Field(ge=0)] | None
    xpe: FiniteNumber | None
    c_score: FiniteNumber | None
    n_rows: Annotated[int, Field(ge=0)]
    n_groups: Annotated[int, Field(ge=0)]
    failure_code: LimitedString100 | None
    evidence_ids: UniqueTuple[EvidenceId]


class PairwiseSwitch(CanonicalModel):
    candidate_a: CandidateId
    candidate_b: CandidateId
    switch_c: FiniteNumber | None
    identifiable: bool
    interpretation: LimitedString1000
    evidence_ids: Annotated[UniqueTuple[EvidenceId], Field(min_length=1)]


class RiecSelection(CanonicalModel):
    schema_logical_name = "riec_selection"

    schema_version: Literal["1.0.0"]
    run_id: RunId
    registry_id: DatasetId
    baseline_candidate_id: Literal["M0_intercept"]
    risk_aggregation: Literal["row_weighted_grouped_mse"]
    c: Annotated[FiniteNumber, Field(ge=0)]
    candidate_ledger: Annotated[
        ImmutableTuple[CandidateLedgerEntry], Field(min_length=1, max_length=32)
    ]
    raw_numeric_winner: CandidateId | None
    runner_up: CandidateId | None
    score_gap: Annotated[FiniteNumber, Field(ge=0)] | None
    decision_status: SelectionDecisionStatus
    equivalence_set: UniqueTuple[CandidateId]
    pairwise_switches: Annotated[ImmutableTuple[PairwiseSwitch], Field(max_length=496)]
    evidence_ids: Annotated[UniqueTuple[EvidenceId], Field(min_length=1)]


class ProtocolId(StrictStrEnum):
    D0_MEAN_DIAGNOSTIC = "D0_mean_diagnostic"
    H1_GROUP_EMPIRICAL_QUANTILE = "H1_group_empirical_quantile"
    H2_GAUSSIAN_RESIDUAL_TAIL = "H2_gaussian_residual_tail"
    H3_STUDENT_T_RESIDUAL_TAIL = "H3_student_t_residual_tail"
    U1_GROUP_BOOTSTRAP_BOUND = "U1_group_bootstrap_bound"
    G1_ORDERED_STABILITY_SCREEN = "G1_ordered_stability_screen"
    G2_EVIDENCE_SUFFICIENCY_GATE = "G2_evidence_sufficiency_gate"


class ProtocolRole(StrictStrEnum):
    DESCRIPTIVE = "descriptive"
    HEADROOM = "headroom"
    UNCERTAINTY = "uncertainty"
    STABILITY_GATE = "stability_gate"
    EVIDENCE_GATE = "evidence_gate"


class ProtocolStatus(StrictStrEnum):
    OK = "ok"
    INELIGIBLE = "ineligible"
    WARNING = "warning"
    FAILED = "failed"


class UncertaintyKind(StrictStrEnum):
    NONE = "none"
    ONE_SIDED_LOWER = "one_sided_lower"
    TWO_SIDED_INTERVAL = "two_sided_interval"


class WarningSeverity(StrictStrEnum):
    INFO = "info"
    WARNING = "warning"
    MATERIAL = "material"
    BLOCKING = "blocking"


class TargetScope(CanonicalModel):
    product_id: LimitedString128
    stream_id: LimitedString128 | None = None


class ProtocolMetric(CanonicalModel):
    name: LimitedString100
    value: JsonValue
    unit: LimitedString32 | None


class ProtocolWarning(CanonicalModel):
    code: ReasonCode
    severity: WarningSeverity
    message: LimitedString1000


class ProtocolUncertainty(CanonicalModel):
    kind: UncertaintyKind
    level: Annotated[FiniteNumber, Field(ge=0, le=1)] | None
    lower: FiniteNumber | None
    upper: FiniteNumber | None
    conditional_on_selection: bool


class ProtocolResultEntry(CanonicalModel):
    protocol_id: ProtocolId
    protocol_version: SemanticVersion
    role: ProtocolRole
    status: ProtocolStatus
    point_estimate: FiniteNumber | None
    unit: LimitedString32 | None = None
    uncertainty: ProtocolUncertainty | None
    metrics: Annotated[ImmutableTuple[ProtocolMetric], Field(max_length=100)]
    warnings: Annotated[ImmutableTuple[ProtocolWarning], Field(max_length=50)]
    evidence_ids: Annotated[UniqueTuple[EvidenceId], Field(min_length=1)]
    runtime_ms: Annotated[int, Field(ge=0)]
    algorithm_notes: LimitedString2000 | None = None


class ProtocolResult(CanonicalModel):
    schema_logical_name = "protocol_result"

    schema_version: Literal["1.0.0"]
    run_id: RunId
    contract_id: ContractId
    target_scope: TargetScope
    results: Annotated[ImmutableTuple[ProtocolResultEntry], Field(min_length=1, max_length=32)]


class ActionState(StrictStrEnum):
    INVALID_CONTRACT = "invalid_contract"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    NO_ACTIONABLE_HEADROOM = "no_actionable_headroom"
    DIAGNOSE_PROCESS_FIRST = "diagnose_process_first"
    PILOT_ONLY_CONSERVATIVE = "pilot_only_conservative"
    PILOT_RANGE_SUPPORTED = "pilot_range_supported"


class HeadroomBasis(StrictStrEnum):
    BOOTSTRAP_LOWER_BOUNDS = "bootstrap_lower_bounds"
    POINT_ESTIMATES_WITHOUT_BOUND = "point_estimates_without_bound"
    NONE = "none"


class HeadroomProtocolId(StrictStrEnum):
    H1_GROUP_EMPIRICAL_QUANTILE = "H1_group_empirical_quantile"
    H2_GAUSSIAN_RESIDUAL_TAIL = "H2_gaussian_residual_tail"
    H3_STUDENT_T_RESIDUAL_TAIL = "H3_student_t_residual_tail"


class OrderedStability(StrictStrEnum):
    PASS = "pass"
    MATERIAL_WARNING = "material_warning"
    INELIGIBLE = "ineligible"


class SafeHeadroom(CanonicalModel):
    value: FiniteNumber | None
    unit: LimitedString32
    basis: HeadroomBasis
    eligible_protocol_ids: UniqueTuple[HeadroomProtocolId]


class PilotReference(CanonicalModel):
    lower: Annotated[FiniteNumber, Field(ge=0)]
    upper: Annotated[FiniteNumber, Field(gt=0)]
    unit: LimitedString32
    rounding_mode: Literal["down_to_measurement_resolution"]
    screening_only: Literal[True]


class ActionGates(CanonicalModel):
    contract_valid: bool
    evidence_sufficient: bool
    ordered_stability: OrderedStability
    zero_headroom_block: bool


class ProtocolConflict(CanonicalModel):
    material_protocol_conflict: bool
    near_tie: bool
    protocol_spread: FiniteNumber | None
    spread_tolerance: Annotated[FiniteNumber, Field(ge=0)]


class ClaimBoundary(CanonicalModel):
    allowed: ImmutableTuple[LimitedString500]
    conditional: ImmutableTuple[LimitedString500]
    prohibited: Annotated[ImmutableTuple[LimitedString500], Field(min_length=1)]


class ActionDecision(CanonicalModel):
    schema_logical_name = "action_decision"

    schema_version: Literal["1.0.0"]
    run_id: RunId
    contract_id: ContractId
    state: ActionState
    reason_codes: Annotated[UniqueTuple[ReasonCode], Field(min_length=1, max_length=50)]
    safe_headroom: SafeHeadroom
    pilot_reference: PilotReference | None
    gates: ActionGates
    conflict: ProtocolConflict
    evidence_ids: Annotated[UniqueTuple[EvidenceId], Field(min_length=1)]
    claim_boundary: ClaimBoundary


class ReportSectionParagraph(CanonicalModel):
    paragraph_id: Annotated[str, StringConstraints(pattern=r"^P-[0-9]{3}$")]
    text_template: Annotated[str, StringConstraints(max_length=5000)]
    claim_ids: UniqueTuple[ClaimId]
    evidence_ids: UniqueTuple[EvidenceId]


class ReportSection(CanonicalModel):
    section_id: Annotated[str, StringConstraints(pattern=r"^SEC-[0-9]{2}$")]
    heading: LimitedString200
    paragraphs: Annotated[
        ImmutableTuple[ReportSectionParagraph], Field(min_length=1, max_length=20)
    ]


class ReportClaim(CanonicalModel):
    claim_id: ClaimId
    claim_text_template: LimitedString3000
    evidence_ids: UniqueTuple[EvidenceId]
    conditional: bool


class NumericBinding(CanonicalModel):
    placeholder: Annotated[str, StringConstraints(pattern=r"^\{\{[a-zA-Z][a-zA-Z0-9_]{0,63}\}\}$")]
    evidence_id: EvidenceId
    json_pointer: Annotated[str, StringConstraints(pattern=r"^/")]
    format_spec: Annotated[str, StringConstraints(max_length=50)]


class ReportDraft(CanonicalModel):
    schema_logical_name = "report_draft"

    schema_version: Literal["1.0.0"]
    run_id: RunId
    title: LimitedString200
    sections: Annotated[ImmutableTuple[ReportSection], Field(min_length=1, max_length=20)]
    claim_map: Annotated[ImmutableTuple[ReportClaim], Field(max_length=200)]
    numeric_bindings: Annotated[ImmutableTuple[NumericBinding], Field(max_length=500)]


class ClaimMateriality(StrictStrEnum):
    HEADLINE = "headline"
    MATERIAL = "material"
    SUPPORTING = "supporting"


class ClaimClassification(StrictStrEnum):
    SUPPORTED = "supported"
    CONDITIONAL = "conditional"
    UNSUPPORTED = "unsupported"
    OVERSTATED = "overstated"
    PROHIBITED = "prohibited"


class ClaimAuditStatus(StrictStrEnum):
    PASS = "pass"
    PASS_WITH_REQUIRED_EDITS = "pass_with_required_edits"
    BLOCK = "block"


class AuditorMode(StrictStrEnum):
    GPT_STRUCTURED_OUTPUT = "gpt_structured_output"
    DETERMINISTIC_ONLY = "deterministic_only"


class DeterministicPrecheck(CanonicalModel):
    passed: bool
    uncited_numbers: ImmutableTuple[LimitedString200]
    unknown_evidence_ids: ImmutableTuple[LimitedString100]
    placeholder_errors: ImmutableTuple[LimitedString500]
    prohibited_phrases: ImmutableTuple[LimitedString500]


class AuditedClaim(CanonicalModel):
    claim_id: ClaimId
    text: Annotated[str, StringConstraints(min_length=1, max_length=3000)]
    materiality: ClaimMateriality
    classification: ClaimClassification
    reason_code: ReasonCode
    evidence_ids: UniqueTuple[EvidenceId]
    required_qualifier: LimitedString1000 | None
    replacement_text: LimitedString3000 | None


class ClaimAuditor(CanonicalModel):
    mode: AuditorMode
    model: LimitedString100 | None
    request_id: LimitedString200 | None
    fallback_used: bool


class ClaimAudit(CanonicalModel):
    schema_logical_name = "claim_audit"

    schema_version: Literal["1.0.0"]
    run_id: RunId
    report_draft_sha256: Sha256
    deterministic_precheck: DeterministicPrecheck
    claims: Annotated[ImmutableTuple[AuditedClaim], Field(max_length=200)]
    overall_status: ClaimAuditStatus
    export_allowed: bool
    auditor: ClaimAuditor = optional_field()


CanonicalRootModel: TypeAlias = type[CanonicalModel]

_MODEL_REGISTRY = {
    "action_decision": ActionDecision,
    "audit_contract": AuditContract,
    "candidate_registry": CandidateRegistry,
    "claim_audit": ClaimAudit,
    "dataset_profile": DatasetProfile,
    "error_envelope": ErrorEnvelope,
    "evidence_ledger": EvidenceLedger,
    "protocol_result": ProtocolResult,
    "report_draft": ReportDraft,
    "riec_selection": RiecSelection,
    "run_manifest": RunManifest,
}
CANONICAL_MODEL_REGISTRY = MappingProxyType(_MODEL_REGISTRY)


class CanonicalModelRegistryError(LookupError):
    """Stable rejection for unknown canonical logical names."""

    code: ClassVar[str] = "CANONICAL_MODEL_NOT_REGISTERED"


def get_canonical_model(logical_name: str) -> CanonicalRootModel:
    try:
        return cast(CanonicalRootModel, CANONICAL_MODEL_REGISTRY[logical_name])
    except KeyError as exc:
        raise CanonicalModelRegistryError(
            "requested logical name has no registered canonical model"
        ) from exc


__all__ = [
    "ActionDecision",
    "AuditContract",
    "CANONICAL_MODEL_REGISTRY",
    "CandidateRegistry",
    "ClaimAudit",
    "DatasetProfile",
    "ProtocolResult",
    "ReportDraft",
    "RiecSelection",
    "get_canonical_model",
]
