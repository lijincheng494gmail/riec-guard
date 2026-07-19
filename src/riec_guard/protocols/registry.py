from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, ValidationError

from riec_guard.contract.models import EvidenceProfile
from riec_guard.errors import (
    CanonicalModel,
    FiniteNumber,
    ImmutableTuple,
    StrictStrEnum,
    UniqueTuple,
)
from riec_guard.riec.registry import (
    ConfigSnapshot,
    RegistryConfigType,
    RegistryErrorCode,
    _load_typed_snapshot,
    _raise,
)

FROZEN_PROTOCOL_CATEGORIES = {
    "D0_mean_diagnostic": "diagnostic",
    "H1_empirical_strict_tail": "headroom_protocol",
    "H2_gaussian_residual_tail": "headroom_protocol",
    "H3_student_t_residual_tail": "headroom_protocol",
    "U1_whole_group_bootstrap": "uncertainty_procedure",
    "G1_ordered_stability_screen": "stability_gate",
    "G2_evidence_sufficiency_gate": "sufficiency_gate",
}
FROZEN_PROTOCOL_IDS = tuple(FROZEN_PROTOCOL_CATEGORIES)
FROZEN_POLICY_INPUT_IDS = (
    "nominal_quantity",
    "lower_limit",
    "alpha",
    "measurement_resolution",
    "minimum_actionable_shift",
    "maximum_screening_shift",
    "protocol_spread_tolerance",
    "quantity_unit",
    "quantity_semantics",
    "conversion_method",
)


class ProtocolCategory(StrictStrEnum):
    DIAGNOSTIC = "diagnostic"
    HEADROOM_PROTOCOL = "headroom_protocol"
    UNCERTAINTY_PROCEDURE = "uncertainty_procedure"
    STABILITY_GATE = "stability_gate"
    SUFFICIENCY_GATE = "sufficiency_gate"


class ProtocolEntry(CanonicalModel):
    object_id: Annotated[str, StringConstraints(pattern=r"^[DHUG][0-9]_[a-z0-9_]+$")]
    version: Annotated[str, StringConstraints(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]
    category: ProtocolCategory
    label: Annotated[str, StringConstraints(min_length=1, max_length=160)]
    enabled: bool
    frozen_before_execution: bool
    role_description: Annotated[str, StringConstraints(min_length=1, max_length=500)]
    required_inputs: UniqueTuple[Annotated[str, StringConstraints(min_length=1, max_length=100)]]
    dependencies: UniqueTuple[Annotated[str, StringConstraints(min_length=1, max_length=100)]]
    output_status_role: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    may_enter_riec_ranking: bool
    requires_confirmed_ordering: bool
    requires_grouped_data: bool
    conditional_on_selection: bool
    reruns_candidate_selection: bool
    calculates_headroom: bool


class ProtocolRegistry(CanonicalModel):
    schema_version: Literal["1.0.0"]
    registry_id: Literal["fill-protocols.v1"]
    registry_version: Literal["1.0.0"]
    frozen_before_execution: Literal[True]
    entries: Annotated[ImmutableTuple[ProtocolEntry], Field(min_length=7, max_length=7)]


class EvidenceProfileConfig(CanonicalModel):
    schema_version: Literal["1.0.0"]
    profile_id: Literal["default-fill-v1"]
    profile_version: Literal["1.0.0"]
    frozen_before_run: Literal[True]
    no_random_row_fallback: Literal[True]
    min_rows: Annotated[int, Field(ge=1, le=100_000)]
    min_groups_exploratory: Annotated[int, Field(ge=2, le=1000)]
    min_groups_action: Annotated[int, Field(ge=2, le=1000)]
    min_expected_tail_count: Annotated[FiniteNumber, Field(ge=1)]
    min_ordered_points_per_stream: Annotated[int, Field(ge=3, le=100_000)]
    minimum_ordered_coverage_fraction: Annotated[FiniteNumber, Field(ge=0, le=1)]
    bootstrap_replicates: Annotated[int, Field(ge=100, le=2000)]
    bootstrap_seed: Annotated[int, Field(ge=0, le=4_294_967_295)]
    bootstrap_min_success: Annotated[int, Field(ge=1, le=2000)]
    bootstrap_max_failed_fraction: Annotated[FiniteNumber, Field(ge=0, le=0.25)]
    bootstrap_one_sided_confidence: Annotated[FiniteNumber, Field(gt=0.5, lt=1)]
    max_exact_logo_groups: Annotated[int, Field(ge=2, le=1000)]

    def to_contract_evidence_profile(self) -> EvidenceProfile:
        """Map the frozen config to TASK-010's exact AuditContract evidence shape."""

        return EvidenceProfile.model_validate(
            {
                "profile_version": self.profile_version,
                "min_rows": self.min_rows,
                "min_groups_exploratory": self.min_groups_exploratory,
                "min_groups_action": self.min_groups_action,
                "min_expected_tail_count": self.min_expected_tail_count,
                "min_ordered_points_per_stream": self.min_ordered_points_per_stream,
                "min_ordered_coverage": self.minimum_ordered_coverage_fraction,
                "bootstrap_replicates": self.bootstrap_replicates,
                "bootstrap_lower_confidence": self.bootstrap_one_sided_confidence,
                "bootstrap_max_failure_fraction": self.bootstrap_max_failed_fraction,
            }
        )


class PolicyValueType(StrictStrEnum):
    NUMBER = "number"
    UNIT = "unit"
    QUANTITY_SEMANTICS = "quantity_semantics"
    CONVERSION_METHOD = "conversion_method"


class PolicyInputDefinition(CanonicalModel):
    input_id: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{2,63}$")]
    version: Literal["1.0.0"]
    category: Literal["policy_input"]
    value_type: PolicyValueType
    required: bool
    confirmation_required: bool
    decision_critical: bool
    validation_rule_reference: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    provenance_requirement: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    may_enter_riec_ranking: Literal[False]


class PolicyInputRegistry(CanonicalModel):
    schema_version: Literal["1.0.0"]
    registry_id: Literal["fill-policy-inputs.v1"]
    registry_version: Literal["1.0.0"]
    frozen_before_run: Literal[True]
    inputs: Annotated[ImmutableTuple[PolicyInputDefinition], Field(min_length=10, max_length=10)]


def load_protocol_registry(
    registry_id: str = "fill-protocols.v1",
    version: str = "1.0.0",
) -> ConfigSnapshot[ProtocolRegistry]:
    """Load typed D0/H1/H2/H3/U1/G1/G2 declarations without algorithms."""

    return _load_typed_snapshot(
        logical_id=registry_id,
        config_type=RegistryConfigType.PROTOCOL_REGISTRY,
        version=version,
        parser=_parse_protocol_registry,
        internal_id_field="registry_id",
        internal_version_field="registry_version",
        frozen_field="frozen_before_execution",
    )


def load_evidence_profile(
    profile_id: str = "default-fill-v1",
    version: str = "1.0.0",
) -> ConfigSnapshot[EvidenceProfileConfig]:
    """Load the immutable evidence and bootstrap threshold profile."""

    return _load_typed_snapshot(
        logical_id=profile_id,
        config_type=RegistryConfigType.EVIDENCE_PROFILE,
        version=version,
        parser=_parse_evidence_profile,
        internal_id_field="profile_id",
        internal_version_field="profile_version",
        frozen_field="frozen_before_run",
    )


def load_policy_input_registry(
    registry_id: str = "fill-policy-inputs.v1",
    version: str = "1.0.0",
) -> ConfigSnapshot[PolicyInputRegistry]:
    """Load governance definitions only; no user policy values are stored here."""

    return _load_typed_snapshot(
        logical_id=registry_id,
        config_type=RegistryConfigType.POLICY_REGISTRY,
        version=version,
        parser=_parse_policy_registry,
        internal_id_field="registry_id",
        internal_version_field="registry_version",
        frozen_field="frozen_before_run",
    )


def _parse_protocol_registry(payload: dict[str, object]) -> ProtocolRegistry:
    if payload.get("frozen_before_execution") is not True:
        _raise(
            RegistryErrorCode.REGISTRY_NOT_FROZEN,
            "Protocol registry must be frozen before execution.",
        )
    raw_entries = payload.get("entries")
    if not isinstance(raw_entries, list):
        _raise(
            RegistryErrorCode.REGISTRY_CONFIG_INVALID,
            "Protocol registry entries must be an ordered array.",
        )
    object_ids: list[str] = []
    raw_categories: dict[str, str] = {}
    for raw_entry in raw_entries:
        if not isinstance(raw_entry, Mapping):
            _raise(
                RegistryErrorCode.REGISTRY_CONFIG_INVALID,
                "Every protocol registry entry must be an object.",
            )
        object_id = raw_entry.get("object_id")
        category = raw_entry.get("category")
        candidate_id = raw_entry.get("candidate_id")
        if (
            isinstance(candidate_id, str)
            or isinstance(object_id, str)
            and object_id.startswith("M")
        ):
            _raise(
                RegistryErrorCode.REGISTRY_CROSS_TYPE_INSERTION,
                "A predictive candidate cannot enter the protocol registry.",
            )
        if category in {
            "predictive_candidate",
            "policy_input",
            "claim_rule",
            "evidence_profile",
        }:
            _raise(
                RegistryErrorCode.REGISTRY_CROSS_TYPE_INSERTION,
                "A candidate, policy, claim, or evidence object cannot enter the protocol registry.",
            )
        if raw_entry.get("may_enter_riec_ranking") is not False:
            _raise(
                RegistryErrorCode.REGISTRY_CROSS_TYPE_INSERTION,
                "A protocol, gate, diagnostic, or uncertainty object cannot enter ranking.",
            )
        if not isinstance(object_id, str) or not isinstance(category, str):
            _raise(
                RegistryErrorCode.REGISTRY_CONFIG_INVALID,
                "Every protocol entry requires a stable ID and category.",
            )
        try:
            ProtocolCategory(category)
        except ValueError:
            _raise(
                RegistryErrorCode.REGISTRY_CATEGORY_INVALID,
                "Protocol registry contains an unknown category.",
            )
        if object_id in object_ids:
            _raise(
                RegistryErrorCode.REGISTRY_DUPLICATE_ID,
                "Protocol stable IDs must be unique across categories.",
            )
        object_ids.append(object_id)
        raw_categories[object_id] = category
    if tuple(object_ids) != FROZEN_PROTOCOL_IDS:
        _raise(
            RegistryErrorCode.REGISTRY_FROZEN_SET_MISMATCH,
            "Protocol membership and order must equal the frozen D0/H1/H2/H3/U1/G1/G2 set.",
        )
    for object_id, expected_category in FROZEN_PROTOCOL_CATEGORIES.items():
        if raw_categories[object_id] != expected_category:
            _raise(
                RegistryErrorCode.REGISTRY_CATEGORY_INVALID,
                "A frozen protocol ID is assigned to the wrong category.",
            )
    try:
        registry = ProtocolRegistry.model_validate(payload)
    except ValidationError:
        _raise(
            RegistryErrorCode.REGISTRY_CONFIG_INVALID,
            "Protocol registry does not satisfy its strict typed contract.",
        )
    for entry in registry.entries:
        if (
            not entry.enabled
            or not entry.frozen_before_execution
            or entry.may_enter_riec_ranking
            or entry.reruns_candidate_selection
            or entry.version != "1.0.0"
        ):
            _raise(
                RegistryErrorCode.REGISTRY_NOT_FROZEN,
                "Protocol entries must be enabled, frozen, and excluded from candidate ranking.",
            )
    entries = {entry.object_id: entry for entry in registry.entries}
    u1 = entries["U1_whole_group_bootstrap"]
    if not u1.conditional_on_selection or u1.reruns_candidate_selection:
        _raise(
            RegistryErrorCode.REGISTRY_CATEGORY_INVALID,
            "U1 must remain conditional on selection and must not rerun selection.",
        )
    if not entries["G1_ordered_stability_screen"].requires_confirmed_ordering:
        _raise(
            RegistryErrorCode.REGISTRY_CATEGORY_INVALID,
            "G1 requires confirmed ordering.",
        )
    if entries["G2_evidence_sufficiency_gate"].calculates_headroom:
        _raise(
            RegistryErrorCode.REGISTRY_CATEGORY_INVALID,
            "G2 is a sufficiency gate and cannot calculate headroom.",
        )
    d0 = entries["D0_mean_diagnostic"]
    if (
        d0.calculates_headroom
        or d0.conditional_on_selection
        or "diagnostic only" not in d0.label.casefold()
        or d0.output_status_role != "diagnostic_context"
    ):
        _raise(
            RegistryErrorCode.REGISTRY_CATEGORY_INVALID,
            "D0 must remain diagnostic only.",
        )
    return registry


def _parse_evidence_profile(payload: dict[str, object]) -> EvidenceProfileConfig:
    if payload.get("frozen_before_run") is not True:
        _raise(
            RegistryErrorCode.REGISTRY_NOT_FROZEN,
            "Evidence profile must be frozen before a run.",
        )
    if payload.get("no_random_row_fallback") is not True:
        _raise(
            RegistryErrorCode.REGISTRY_CROSS_TYPE_INSERTION,
            "Evidence configuration cannot introduce random-row fallback.",
        )
    try:
        profile = EvidenceProfileConfig.model_validate(payload)
    except ValidationError:
        _raise(
            RegistryErrorCode.REGISTRY_CONFIG_INVALID,
            "Evidence profile does not satisfy its strict bounded contract.",
        )
    if profile.min_groups_action < profile.min_groups_exploratory:
        _raise(
            RegistryErrorCode.REGISTRY_CONFIG_INVALID,
            "Action group minimum cannot be below exploratory group minimum.",
        )
    if profile.bootstrap_min_success > profile.bootstrap_replicates:
        _raise(
            RegistryErrorCode.REGISTRY_CONFIG_INVALID,
            "Bootstrap minimum success cannot exceed replicate count.",
        )
    profile.to_contract_evidence_profile()
    return profile


def _parse_policy_registry(payload: dict[str, object]) -> PolicyInputRegistry:
    if payload.get("frozen_before_run") is not True:
        _raise(
            RegistryErrorCode.REGISTRY_NOT_FROZEN,
            "Policy-input registry must be frozen before a run.",
        )
    raw_inputs = payload.get("inputs")
    if not isinstance(raw_inputs, list):
        _raise(
            RegistryErrorCode.REGISTRY_CONFIG_INVALID,
            "Policy inputs must be a fixed ordered array.",
        )
    input_ids: list[str] = []
    for raw_input in raw_inputs:
        if not isinstance(raw_input, Mapping):
            _raise(
                RegistryErrorCode.REGISTRY_CONFIG_INVALID,
                "Every policy definition must be an object.",
            )
        input_id = raw_input.get("input_id")
        category = raw_input.get("category")
        if category != "policy_input":
            if category is not None:
                _raise(
                    RegistryErrorCode.REGISTRY_CROSS_TYPE_INSERTION,
                    "A non-policy object cannot enter the policy-input registry.",
                )
            _raise(
                RegistryErrorCode.REGISTRY_CATEGORY_INVALID,
                "Policy definitions require the policy_input category.",
            )
        if raw_input.get("may_enter_riec_ranking") is not False:
            _raise(
                RegistryErrorCode.REGISTRY_CROSS_TYPE_INSERTION,
                "Policy inputs cannot enter predictive candidate ranking.",
            )
        if not isinstance(input_id, str):
            _raise(
                RegistryErrorCode.REGISTRY_CONFIG_INVALID,
                "Every policy definition requires a stable ID.",
            )
        if input_id in input_ids:
            _raise(
                RegistryErrorCode.REGISTRY_DUPLICATE_ID,
                "Policy input IDs must be unique.",
            )
        input_ids.append(input_id)
    if tuple(input_ids) != FROZEN_POLICY_INPUT_IDS:
        _raise(
            RegistryErrorCode.REGISTRY_FROZEN_SET_MISMATCH,
            "Policy-input membership and order must equal the frozen governance set.",
        )
    try:
        registry = PolicyInputRegistry.model_validate(payload)
    except ValidationError:
        _raise(
            RegistryErrorCode.REGISTRY_CONFIG_INVALID,
            "Policy-input registry does not satisfy its strict typed contract.",
        )
    for item in registry.inputs:
        if item.may_enter_riec_ranking:
            _raise(
                RegistryErrorCode.REGISTRY_CROSS_TYPE_INSERTION,
                "Policy inputs cannot enter predictive candidate ranking.",
            )
        if item.decision_critical and not item.confirmation_required:
            _raise(
                RegistryErrorCode.REGISTRY_CONFIG_INVALID,
                "Every decision-critical policy input requires explicit confirmation.",
            )
    return registry


__all__ = [
    "EvidenceProfileConfig",
    "FROZEN_POLICY_INPUT_IDS",
    "FROZEN_PROTOCOL_CATEGORIES",
    "FROZEN_PROTOCOL_IDS",
    "PolicyInputDefinition",
    "PolicyInputRegistry",
    "ProtocolCategory",
    "ProtocolEntry",
    "ProtocolRegistry",
    "load_evidence_profile",
    "load_policy_input_registry",
    "load_protocol_registry",
]
