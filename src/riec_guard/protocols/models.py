"""Typed internal results for the deterministic Fill protocol layer.

The canonical JSON models deliberately have a compact public shape.  These
immutable helpers retain the execution semantics needed by the action engine
without widening the frozen schemas or exposing row-level observations.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TypeAlias

from riec_guard.contract.models import (
    ProtocolId,
    ProtocolMetric,
    ProtocolResultEntry,
    ProtocolRole,
    ProtocolStatus,
    ProtocolUncertainty,
    ProtocolWarning,
    UncertaintyKind,
    WarningSeverity,
)

MetricValue: TypeAlias = float | int | str | bool | None | tuple[float, ...]


class ProtocolReasonCode(StrEnum):
    """Stable implementation-v1 protocol and gate reason codes."""

    EMPIRICAL_BASELINE_EXCEEDS_TAIL_LIMIT = "EMPIRICAL_BASELINE_EXCEEDS_TAIL_LIMIT"
    EMPIRICAL_BOUNDARY_TIE = "EMPIRICAL_BOUNDARY_TIE"
    EMPIRICAL_INSUFFICIENT_GROUPS = "EMPIRICAL_INSUFFICIENT_GROUPS"
    EMPIRICAL_INSUFFICIENT_ROWS = "EMPIRICAL_INSUFFICIENT_ROWS"
    EMPIRICAL_INSUFFICIENT_TAIL_SUPPORT = "EMPIRICAL_INSUFFICIENT_TAIL_SUPPORT"
    EMPIRICAL_INVALID_INPUT = "EMPIRICAL_INVALID_INPUT"
    PARAMETRIC_INSUFFICIENT_SUPPORT = "PARAMETRIC_INSUFFICIENT_SUPPORT"
    PARAMETRIC_DEGENERATE_SCALE = "PARAMETRIC_DEGENERATE_SCALE"
    PARAMETRIC_SEARCH_CENSORED = "PARAMETRIC_SEARCH_CENSORED"
    RESIDUAL_SKEW_DIAGNOSTIC = "RESIDUAL_SKEW_DIAGNOSTIC"
    HEAVY_TAIL_DIAGNOSTIC = "HEAVY_TAIL_DIAGNOSTIC"
    GROUPWISE_SCALE_DIAGNOSTIC = "GROUPWISE_SCALE_DIAGNOSTIC"
    STUDENT_T_FIT_TIMEOUT = "STUDENT_T_FIT_TIMEOUT"
    STUDENT_T_FIT_NONCONVERGENCE = "STUDENT_T_FIT_NONCONVERGENCE"
    STUDENT_T_DF_BOUNDARY = "STUDENT_T_DF_BOUNDARY"
    BOOTSTRAP_INSUFFICIENT_GROUPS = "BOOTSTRAP_INSUFFICIENT_GROUPS"
    BOOTSTRAP_INSUFFICIENT_SUCCESS = "BOOTSTRAP_INSUFFICIENT_SUCCESS"
    BOOTSTRAP_FAILURE_FRACTION = "BOOTSTRAP_FAILURE_FRACTION"
    ORDER_UNCONFIRMED = "ORDER_UNCONFIRMED"
    ORDER_STREAM_UNAVAILABLE = "ORDER_STREAM_UNAVAILABLE"
    ORDER_TIE_UNRESOLVED = "ORDER_TIE_UNRESOLVED"
    ORDERED_COVERAGE_INSUFFICIENT = "ORDERED_COVERAGE_INSUFFICIENT"
    MR_SCALE_FALLBACK = "MR_SCALE_FALLBACK"
    STABILITY_POINT_BEYOND_3SIGMA = "STABILITY_POINT_BEYOND_3SIGMA"
    STABILITY_EIGHT_ONE_SIDE = "STABILITY_EIGHT_ONE_SIDE"
    STABILITY_SIX_MONOTONE = "STABILITY_SIX_MONOTONE"
    STABILITY_QUARTILE_SHIFT = "STABILITY_QUARTILE_SHIFT"
    EVIDENCE_ROWS_INSUFFICIENT = "EVIDENCE_ROWS_INSUFFICIENT"
    EVIDENCE_GROUPS_EXPLORATORY_INSUFFICIENT = "EVIDENCE_GROUPS_EXPLORATORY_INSUFFICIENT"
    EVIDENCE_GROUPS_ACTION_INSUFFICIENT = "EVIDENCE_GROUPS_ACTION_INSUFFICIENT"
    EVIDENCE_TAIL_SUPPORT_INSUFFICIENT = "EVIDENCE_TAIL_SUPPORT_INSUFFICIENT"
    EVIDENCE_BOOTSTRAP_INSUFFICIENT = "EVIDENCE_BOOTSTRAP_INSUFFICIENT"
    EVIDENCE_ORDER_INSUFFICIENT = "EVIDENCE_ORDER_INSUFFICIENT"
    EVIDENCE_MEASUREMENT_INSUFFICIENT = "EVIDENCE_MEASUREMENT_INSUFFICIENT"


class G1Status(StrEnum):
    PASS = "pass"
    MATERIAL_WARNING = "material_warning"
    INELIGIBLE = "ineligible"


@dataclass(frozen=True, slots=True)
class Metric:
    name: str
    value: MetricValue
    unit: str | None = None

    def canonical(self) -> ProtocolMetric:
        value: object = list(self.value) if isinstance(self.value, tuple) else self.value
        return ProtocolMetric.model_validate({"name": self.name, "value": value, "unit": self.unit})


@dataclass(frozen=True, slots=True)
class Warning:
    code: ProtocolReasonCode
    severity: WarningSeverity
    message: str

    def canonical(self) -> ProtocolWarning:
        return ProtocolWarning.model_validate(
            {
                "code": self.code.value,
                "severity": self.severity,
                "message": self.message,
            }
        )


@dataclass(frozen=True, slots=True)
class Uncertainty:
    kind: UncertaintyKind
    level: float | None
    lower: float | None
    upper: float | None
    conditional_on_selection: bool

    @classmethod
    def none(cls) -> Uncertainty:
        return cls(
            kind=UncertaintyKind.NONE,
            level=None,
            lower=None,
            upper=None,
            conditional_on_selection=False,
        )

    def canonical(self) -> ProtocolUncertainty:
        return ProtocolUncertainty.model_validate(
            {
                "kind": self.kind,
                "level": self.level,
                "lower": self.lower,
                "upper": self.upper,
                "conditional_on_selection": self.conditional_on_selection,
            }
        )


@dataclass(frozen=True, slots=True)
class ProtocolComputation:
    protocol_id: ProtocolId
    role: ProtocolRole
    status: ProtocolStatus
    point_estimate: float | None
    unit: str | None
    uncertainty: Uncertainty
    metrics: tuple[Metric, ...]
    warnings: tuple[Warning, ...]
    algorithm_notes: str

    @property
    def material_warning(self) -> bool:
        return any(
            warning.severity in {WarningSeverity.MATERIAL, WarningSeverity.BLOCKING}
            for warning in self.warnings
        )

    @property
    def eligible_headroom(self) -> bool:
        return (
            self.role is ProtocolRole.HEADROOM
            and self.status in {ProtocolStatus.OK, ProtocolStatus.WARNING}
            and self.point_estimate is not None
            and math.isfinite(self.point_estimate)
            and self.point_estimate >= 0.0
        )

    def metric(self, name: str) -> MetricValue | None:
        for item in self.metrics:
            if item.name == name:
                return item.value
        return None

    def with_uncertainty(self, uncertainty: Uncertainty) -> ProtocolComputation:
        return replace(self, uncertainty=uncertainty)

    def to_canonical_entry(self, *, evidence_ids: tuple[str, ...]) -> ProtocolResultEntry:
        """Project to the frozen schema with deterministic runtime identity."""

        return ProtocolResultEntry.model_validate(
            {
                "protocol_id": self.protocol_id,
                "protocol_version": "1.0.0",
                "role": self.role,
                "status": self.status,
                "point_estimate": self.point_estimate,
                "unit": self.unit,
                "uncertainty": self.uncertainty.canonical(),
                "metrics": tuple(metric.canonical() for metric in self.metrics),
                "warnings": tuple(warning.canonical() for warning in self.warnings),
                "evidence_ids": evidence_ids,
                # Wall time is telemetry, not canonical artifact identity.
                "runtime_ms": 0,
                "algorithm_notes": self.algorithm_notes,
            }
        )


@dataclass(frozen=True, slots=True)
class CrossFittedPrediction:
    candidate_id: str
    predictions: tuple[float, ...]


@dataclass(frozen=True, slots=True)
class BootstrapSummary:
    computation: ProtocolComputation
    lower_bounds: tuple[tuple[ProtocolId, float], ...]
    requested_replicates: int
    successful_replicates: int
    failed_replicates: int
    failure_codes: tuple[str, ...]

    @property
    def valid(self) -> bool:
        return self.computation.status in {ProtocolStatus.OK, ProtocolStatus.WARNING}

    def lower_bound(self, protocol_id: ProtocolId) -> float | None:
        for candidate_id, value in self.lower_bounds:
            if candidate_id is protocol_id:
                return value
        return None


@dataclass(frozen=True, slots=True)
class StabilitySummary:
    computation: ProtocolComputation
    state: G1Status
    ordered_coverage: float


@dataclass(frozen=True, slots=True)
class SufficiencySummary:
    computation: ProtocolComputation
    exploratory_supported: bool
    action_supported: bool
    reason_codes: tuple[ProtocolReasonCode, ...]


__all__ = [
    "BootstrapSummary",
    "CrossFittedPrediction",
    "G1Status",
    "Metric",
    "ProtocolComputation",
    "ProtocolReasonCode",
    "StabilitySummary",
    "SufficiencySummary",
    "Uncertainty",
    "Warning",
]
