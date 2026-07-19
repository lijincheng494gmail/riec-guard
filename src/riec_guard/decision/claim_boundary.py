from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, ValidationError

from riec_guard.errors import CanonicalModel, ImmutableTuple, StrictStrEnum, UniqueTuple
from riec_guard.riec.registry import (
    ConfigSnapshot,
    RegistryConfigType,
    RegistryErrorCode,
    _load_typed_snapshot,
    _raise,
)

FROZEN_CLAIM_CLASSES = (
    "supported",
    "conditional",
    "unsupported",
    "overstated",
    "prohibited",
)
FROZEN_PROHIBITED_CONCEPTS = (
    "achieved_savings",
    "compliance_guarantee",
    "optimal_production_setpoint",
    "safe_production_setpoint",
    "successful_live_deployment",
    "causal_improvement",
    "universal_cross_domain_validity",
    "zero_underfill_risk",
    "replaces_engineers",
)
FROZEN_BOUNDARY_CONCEPTS = (
    "retrospective_screening_analysis",
    "no_autonomous_control",
    "no_compliance_certification",
    "no_achieved_savings_evidence",
    "no_direct_setpoint_recommendation",
    "controlled_pilot_and_engineering_review_required",
)
MANDATORY_RETROSPECTIVE_PHRASE = "retrospective screening reference"
FROZEN_EXPORT_RULE_IDS = (
    "prohibited_material_or_headline_claim",
    "unresolved_unsupported_or_overstated_material_or_headline",
    "conditional_claim_missing_required_qualifier",
    "deterministic_precheck_failure",
    "supporting_removal_hides_material_limitations",
)


class ClaimClass(StrictStrEnum):
    SUPPORTED = "supported"
    CONDITIONAL = "conditional"
    UNSUPPORTED = "unsupported"
    OVERSTATED = "overstated"
    PROHIBITED = "prohibited"


class ExportEnforcementRule(CanonicalModel):
    rule_id: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{2,127}$")]
    version: Literal["1.0.0"]
    category: Literal["claim_rule"]
    description: Annotated[str, StringConstraints(min_length=1, max_length=500)]
    blocks_export: Literal[True]


class ClaimRuleset(CanonicalModel):
    schema_version: Literal["1.0.0"]
    ruleset_id: Literal["fill-claims-v1"]
    ruleset_version: Literal["1.0.0"]
    frozen_before_audit: Literal[True]
    claim_classes: UniqueTuple[ClaimClass]
    prohibited_without_separate_evidence: UniqueTuple[
        Annotated[str, StringConstraints(min_length=1, max_length=100)]
    ]
    mandatory_boundary_concepts: UniqueTuple[
        Annotated[str, StringConstraints(min_length=1, max_length=100)]
    ]
    mandatory_phrase: Literal["retrospective screening reference"]
    export_enforcement_rules: Annotated[
        ImmutableTuple[ExportEnforcementRule], Field(min_length=5, max_length=5)
    ]


def load_claim_ruleset(
    ruleset_id: str = "fill-claims-v1",
    version: str = "1.0.0",
) -> ConfigSnapshot[ClaimRuleset]:
    """Load the frozen claim boundary without performing free-text classification."""

    return _load_typed_snapshot(
        logical_id=ruleset_id,
        config_type=RegistryConfigType.CLAIM_RULESET,
        version=version,
        parser=_parse_claim_ruleset,
        internal_id_field="ruleset_id",
        internal_version_field="ruleset_version",
        frozen_field="frozen_before_audit",
    )


def list_valid_claim_classes(
    snapshot: ConfigSnapshot[ClaimRuleset] | None = None,
) -> tuple[ClaimClass, ...]:
    """Return the immutable five-class claim taxonomy."""

    ruleset = (snapshot or load_claim_ruleset()).payload
    return tuple(ruleset.claim_classes)


def is_prohibited_without_external_evidence(
    concept: str,
    snapshot: ConfigSnapshot[ClaimRuleset] | None = None,
) -> bool:
    """Query the fixed prohibited-concept set without interpreting free text."""

    ruleset = (snapshot or load_claim_ruleset()).payload
    return concept in ruleset.prohibited_without_separate_evidence


def mandatory_boundary_concepts(
    snapshot: ConfigSnapshot[ClaimRuleset] | None = None,
) -> tuple[str, ...]:
    """Return visible boundary concepts required in every approved memo."""

    ruleset = (snapshot or load_claim_ruleset()).payload
    return tuple(ruleset.mandatory_boundary_concepts)


def deterministic_export_blocking_rules(
    snapshot: ConfigSnapshot[ClaimRuleset] | None = None,
) -> tuple[ExportEnforcementRule, ...]:
    """Return fixed deterministic enforcement declarations; no NLP is run here."""

    ruleset = (snapshot or load_claim_ruleset()).payload
    return tuple(ruleset.export_enforcement_rules)


def _parse_claim_ruleset(payload: dict[str, object]) -> ClaimRuleset:
    if payload.get("frozen_before_audit") is not True:
        _raise(
            RegistryErrorCode.REGISTRY_NOT_FROZEN,
            "Claim ruleset must be frozen before audit.",
        )
    raw_classes = payload.get("claim_classes")
    if not isinstance(raw_classes, list) or not all(isinstance(item, str) for item in raw_classes):
        _raise(
            RegistryErrorCode.REGISTRY_CONFIG_INVALID,
            "Claim classes must be a fixed string array.",
        )
    if len(set(raw_classes)) != len(raw_classes):
        _raise(
            RegistryErrorCode.REGISTRY_DUPLICATE_ID,
            "Claim classes must be unique.",
        )
    for raw_class in raw_classes:
        try:
            ClaimClass(raw_class)
        except ValueError:
            _raise(
                RegistryErrorCode.REGISTRY_CATEGORY_INVALID,
                "Claim ruleset contains an unknown claim class.",
            )
    if tuple(raw_classes) != FROZEN_CLAIM_CLASSES:
        _raise(
            RegistryErrorCode.REGISTRY_FROZEN_SET_MISMATCH,
            "Claim classes must equal the frozen five-class taxonomy.",
        )
    _validate_unique_frozen_strings(
        payload,
        "prohibited_without_separate_evidence",
        FROZEN_PROHIBITED_CONCEPTS,
        "prohibited claim concepts",
    )
    _validate_unique_frozen_strings(
        payload,
        "mandatory_boundary_concepts",
        FROZEN_BOUNDARY_CONCEPTS,
        "mandatory claim-boundary concepts",
    )
    if payload.get("mandatory_phrase") != MANDATORY_RETROSPECTIVE_PHRASE:
        _raise(
            RegistryErrorCode.REGISTRY_FROZEN_SET_MISMATCH,
            "The mandatory retrospective screening phrase must be preserved.",
        )
    raw_rules = payload.get("export_enforcement_rules")
    if not isinstance(raw_rules, list):
        _raise(
            RegistryErrorCode.REGISTRY_CONFIG_INVALID,
            "Export enforcement rules must be a fixed array.",
        )
    rule_ids: list[str] = []
    for raw_rule in raw_rules:
        if not isinstance(raw_rule, Mapping):
            _raise(
                RegistryErrorCode.REGISTRY_CONFIG_INVALID,
                "Every export enforcement rule must be an object.",
            )
        rule_id = raw_rule.get("rule_id")
        category = raw_rule.get("category")
        object_id = raw_rule.get("object_id")
        if category != "claim_rule":
            if category is not None or isinstance(object_id, str):
                _raise(
                    RegistryErrorCode.REGISTRY_CROSS_TYPE_INSERTION,
                    "A protocol, gate, policy, or candidate cannot enter the claim ruleset.",
                )
            _raise(
                RegistryErrorCode.REGISTRY_CATEGORY_INVALID,
                "Export rules require the claim_rule category.",
            )
        if not isinstance(rule_id, str):
            _raise(
                RegistryErrorCode.REGISTRY_CONFIG_INVALID,
                "Every export rule requires a stable rule ID.",
            )
        if rule_id in rule_ids:
            _raise(
                RegistryErrorCode.REGISTRY_DUPLICATE_ID,
                "Export rule IDs must be unique.",
            )
        rule_ids.append(rule_id)
    if tuple(rule_ids) != FROZEN_EXPORT_RULE_IDS:
        _raise(
            RegistryErrorCode.REGISTRY_FROZEN_SET_MISMATCH,
            "Export enforcement rules must equal the frozen claim-boundary set.",
        )
    try:
        return ClaimRuleset.model_validate(payload)
    except ValidationError:
        _raise(
            RegistryErrorCode.REGISTRY_CONFIG_INVALID,
            "Claim ruleset does not satisfy its strict typed contract.",
        )


def _validate_unique_frozen_strings(
    payload: dict[str, object],
    field: str,
    expected: tuple[str, ...],
    label: str,
) -> None:
    values = payload.get(field)
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        _raise(
            RegistryErrorCode.REGISTRY_CONFIG_INVALID,
            f"The {label} must be a fixed string array.",
        )
    if len(set(values)) != len(values):
        _raise(
            RegistryErrorCode.REGISTRY_DUPLICATE_ID,
            f"The {label} must be unique.",
        )
    if tuple(values) != expected:
        _raise(
            RegistryErrorCode.REGISTRY_FROZEN_SET_MISMATCH,
            f"The {label} must match the frozen ruleset.",
        )


__all__ = [
    "ClaimClass",
    "ClaimRuleset",
    "ExportEnforcementRule",
    "FROZEN_BOUNDARY_CONCEPTS",
    "FROZEN_CLAIM_CLASSES",
    "FROZEN_PROHIBITED_CONCEPTS",
    "MANDATORY_RETROSPECTIVE_PHRASE",
    "deterministic_export_blocking_rules",
    "is_prohibited_without_external_evidence",
    "list_valid_claim_classes",
    "load_claim_ruleset",
    "mandatory_boundary_concepts",
]
