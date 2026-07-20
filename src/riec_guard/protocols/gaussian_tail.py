"""Diagnostic Gaussian residual-tail Fill protocol."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Callable

from riec_guard.contract.models import (
    ProtocolId,
    ProtocolRole,
    ProtocolStatus,
    UncertaintyKind,
    WarningSeverity,
)
from riec_guard.protocols.models import (
    CrossFittedPrediction,
    Metric,
    ProtocolComputation,
    ProtocolReasonCode,
    Uncertainty,
    Warning,
)

GAUSSIAN_ESTIMATOR_VERSION = "sample-mean-sample-sd.v1"
BISECTION_TOLERANCE = 1.0e-9
BISECTION_MAX_ITERATIONS = 80
DEGENERATE_SCALE_EPSILON = 1.0e-12
SKEWNESS_MATERIAL_THRESHOLD = 1.0
EXCESS_KURTOSIS_MATERIAL_THRESHOLD = 3.0
GROUPWISE_SCALE_RATIO_MATERIAL_THRESHOLD = 2.0


@dataclass(frozen=True, slots=True)
class _ResidualDiagnostics:
    location: float
    scale: float
    skewness: float
    excess_kurtosis: float
    groupwise_scale_ratio: float | None
    groupwise_scale_unbounded: bool


@dataclass(frozen=True, slots=True)
class _SearchResult:
    headroom: float
    baseline_risk: float
    terminal_risk: float
    iterations: int
    right_censored: bool
    baseline_feasible: bool


def run_gaussian_residual_tail(
    quantities: tuple[float, ...],
    group_tokens: tuple[str, ...],
    cross_fitted: tuple[CrossFittedPrediction, ...],
    *,
    lower_limit: float,
    alpha: float,
    maximum_screening_shift: float,
    unit: str,
) -> ProtocolComputation:
    """Fit declared Gaussian residual estimators and solve tail risk exactly.

    Each equivalence-set candidate uses grouped cross-fitted predictions.  The
    protocol's point estimate is the minimum eligible candidate headroom; no
    Gaussian result is labelled automatically conservative.
    """

    validated = _validate_tail_inputs(
        quantities,
        group_tokens,
        cross_fitted,
        lower_limit=lower_limit,
        alpha=alpha,
        maximum_screening_shift=maximum_screening_shift,
        unit=unit,
    )
    if validated is None:
        return _failed_tail_computation(
            ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL,
            unit,
            "H2 requires finite aligned quantities, groups, predictions, policy, and unit.",
        )
    values, groups, models = validated
    if len(values) < 4 or len(set(groups)) < 2:
        return _ineligible_tail_computation(
            ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL,
            unit,
            "H2 needs at least four residuals across at least two deployment groups.",
        )

    diagnostics: list[_ResidualDiagnostics] = []
    searches: list[_SearchResult] = []
    eligible_candidate_ids: list[str] = []
    degenerate_count = 0
    for model in models:
        residuals = tuple(
            observed - predicted
            for observed, predicted in zip(values, model.predictions, strict=True)
        )
        candidate_diagnostics = _residual_diagnostics(residuals, groups)
        if candidate_diagnostics is None:
            degenerate_count += 1
            continue
        risk = _tail_risk_function(
            model.predictions,
            lower_limit=float(lower_limit),
            location=candidate_diagnostics.location,
            scale=candidate_diagnostics.scale,
            cdf=_standard_normal_cdf,
        )
        search = _solve_maximum_shift(
            risk,
            alpha=float(alpha),
            maximum_shift=float(maximum_screening_shift),
        )
        diagnostics.append(candidate_diagnostics)
        searches.append(search)
        eligible_candidate_ids.append(model.candidate_id)

    warnings: list[Warning] = []
    if degenerate_count:
        warnings.append(
            Warning(
                ProtocolReasonCode.PARAMETRIC_DEGENERATE_SCALE,
                WarningSeverity.MATERIAL,
                "One or more Gaussian residual fits had degenerate sample scale and were "
                "excluded without substitution.",
            )
        )
    if not searches:
        warnings.append(
            Warning(
                ProtocolReasonCode.PARAMETRIC_INSUFFICIENT_SUPPORT,
                WarningSeverity.BLOCKING,
                "No Gaussian equivalence-set member produced an eligible residual fit.",
            )
        )
        return _tail_result(
            protocol_id=ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL,
            status=ProtocolStatus.INELIGIBLE,
            point_estimate=None,
            unit=unit,
            metrics=(
                Metric("n", len(values)),
                Metric("n_groups", len(set(groups))),
                Metric("candidate_count_requested", len(models)),
                Metric("candidate_count_eligible", 0),
                Metric("degenerate_scale_count", degenerate_count),
                Metric("residual_estimator", GAUSSIAN_ESTIMATOR_VERSION),
            ),
            warnings=tuple(warnings),
            notes=(
                "Cross-fitted Gaussian residual-tail risk; no silent parametric or "
                "empirical fallback was used."
            ),
        )

    maximum_abs_skewness = max(abs(item.skewness) for item in diagnostics)
    maximum_excess_kurtosis = max(item.excess_kurtosis for item in diagnostics)
    finite_scale_ratios = tuple(
        item.groupwise_scale_ratio for item in diagnostics if item.groupwise_scale_ratio is not None
    )
    maximum_scale_ratio = max(finite_scale_ratios, default=None)
    unbounded_scale_ratio = any(item.groupwise_scale_unbounded for item in diagnostics)
    baseline_infeasible_count = sum(not search.baseline_feasible for search in searches)
    right_censored_count = sum(search.right_censored for search in searches)

    if maximum_abs_skewness > SKEWNESS_MATERIAL_THRESHOLD:
        warnings.append(
            Warning(
                ProtocolReasonCode.RESIDUAL_SKEW_DIAGNOSTIC,
                WarningSeverity.MATERIAL,
                "Residual absolute skewness exceeds the implementation-v1 material threshold.",
            )
        )
    if maximum_excess_kurtosis > EXCESS_KURTOSIS_MATERIAL_THRESHOLD:
        warnings.append(
            Warning(
                ProtocolReasonCode.HEAVY_TAIL_DIAGNOSTIC,
                WarningSeverity.MATERIAL,
                "Residual excess kurtosis exceeds the implementation-v1 material threshold.",
            )
        )
    if (
        unbounded_scale_ratio
        or maximum_scale_ratio is not None
        and maximum_scale_ratio > GROUPWISE_SCALE_RATIO_MATERIAL_THRESHOLD
    ):
        warnings.append(
            Warning(
                ProtocolReasonCode.GROUPWISE_SCALE_DIAGNOSTIC,
                WarningSeverity.MATERIAL,
                "Residual groupwise scale heterogeneity exceeds the implementation-v1 "
                "material threshold.",
            )
        )
    if baseline_infeasible_count:
        warnings.append(
            Warning(
                ProtocolReasonCode.PARAMETRIC_INSUFFICIENT_SUPPORT,
                WarningSeverity.MATERIAL,
                "At least one fitted Gaussian model exceeds alpha before any reduction; its "
                "headroom is zero.",
            )
        )
    if right_censored_count:
        warnings.append(
            Warning(
                ProtocolReasonCode.PARAMETRIC_SEARCH_CENSORED,
                WarningSeverity.WARNING,
                "At least one Gaussian headroom remains feasible at the predeclared search "
                "maximum and is reported as right-censored there.",
            )
        )

    headrooms = tuple(search.headroom for search in searches)
    status = ProtocolStatus.WARNING if warnings else ProtocolStatus.OK
    return _tail_result(
        protocol_id=ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL,
        status=status,
        point_estimate=min(headrooms),
        unit=unit,
        metrics=(
            Metric("n", len(values)),
            Metric("n_groups", len(set(groups))),
            Metric("alpha", float(alpha)),
            Metric("candidate_count_requested", len(models)),
            Metric("candidate_count_eligible", len(searches)),
            Metric("eligible_candidate_ids", ",".join(eligible_candidate_ids)),
            Metric("candidate_headrooms", headrooms, unit),
            Metric("residual_location_min", min(item.location for item in diagnostics), unit),
            Metric("residual_location_max", max(item.location for item in diagnostics), unit),
            Metric("residual_scale_min", min(item.scale for item in diagnostics), unit),
            Metric("residual_scale_max", max(item.scale for item in diagnostics), unit),
            Metric("residual_skewness_max_abs", maximum_abs_skewness),
            Metric("residual_excess_kurtosis_max", maximum_excess_kurtosis),
            Metric("groupwise_scale_ratio_max", maximum_scale_ratio),
            Metric("groupwise_scale_ratio_unbounded", unbounded_scale_ratio),
            Metric("baseline_tail_risk_max", max(item.baseline_risk for item in searches)),
            Metric("terminal_tail_risk_max", max(item.terminal_risk for item in searches)),
            Metric("baseline_infeasible_count", baseline_infeasible_count),
            Metric("right_censored_count", right_censored_count),
            Metric("degenerate_scale_count", degenerate_count),
            Metric("search_lower_bound", 0.0, unit),
            Metric("search_upper_bound", float(maximum_screening_shift), unit),
            Metric("bisection_tolerance", BISECTION_TOLERANCE, unit),
            Metric("bisection_iterations_max", max(item.iterations for item in searches)),
            Metric("residual_estimator", GAUSSIAN_ESTIMATOR_VERSION),
            Metric("skewness_material_threshold", SKEWNESS_MATERIAL_THRESHOLD),
            Metric("excess_kurtosis_material_threshold", EXCESS_KURTOSIS_MATERIAL_THRESHOLD),
            Metric(
                "groupwise_scale_ratio_material_threshold",
                GROUPWISE_SCALE_RATIO_MATERIAL_THRESHOLD,
            ),
        ),
        warnings=tuple(warnings),
        notes=(
            "Cross-fitted Gaussian residual-tail risk using sample mean and sample SD; "
            "deterministic bisection and minimum aggregation across the frozen equivalence set."
        ),
    )


def _validate_tail_inputs(
    quantities: tuple[float, ...],
    group_tokens: tuple[str, ...],
    cross_fitted: tuple[CrossFittedPrediction, ...],
    *,
    lower_limit: float,
    alpha: float,
    maximum_screening_shift: float,
    unit: str,
) -> (
    tuple[
        tuple[float, ...],
        tuple[str, ...],
        tuple[CrossFittedPrediction, ...],
    ]
    | None
):
    if (
        not isinstance(quantities, tuple)
        or not quantities
        or any(not _is_finite_number(value) for value in quantities)
        or not isinstance(group_tokens, tuple)
        or len(group_tokens) != len(quantities)
        or any(not isinstance(group, str) or not group for group in group_tokens)
        or not isinstance(cross_fitted, tuple)
        or not cross_fitted
        or not _is_finite_number(lower_limit)
        or not _is_finite_number(alpha)
        or not 0.0 < float(alpha) < 0.5
        or not _is_finite_number(maximum_screening_shift)
        or float(maximum_screening_shift) <= 0.0
        or not isinstance(unit, str)
        or not 0 < len(unit) <= 32
    ):
        return None
    candidate_ids: set[str] = set()
    models: list[CrossFittedPrediction] = []
    for item in cross_fitted:
        if (
            not isinstance(item, CrossFittedPrediction)
            or not item.candidate_id
            or item.candidate_id in candidate_ids
            or not isinstance(item.predictions, tuple)
            or len(item.predictions) != len(quantities)
            or any(not _is_finite_number(value) for value in item.predictions)
        ):
            return None
        candidate_ids.add(item.candidate_id)
        models.append(
            CrossFittedPrediction(
                candidate_id=item.candidate_id,
                predictions=tuple(float(value) for value in item.predictions),
            )
        )
    return (
        tuple(float(value) for value in quantities),
        group_tokens,
        tuple(models),
    )


def _residual_diagnostics(
    residuals: tuple[float, ...],
    groups: tuple[str, ...],
) -> _ResidualDiagnostics | None:
    n_rows = len(residuals)
    location = math.fsum(residuals) / n_rows
    centered = tuple(value - location for value in residuals)
    sum_squares = math.fsum(value * value for value in centered)
    scale = math.sqrt(sum_squares / (n_rows - 1))
    if not math.isfinite(scale) or scale <= DEGENERATE_SCALE_EPSILON:
        return None
    standardized = tuple(value / scale for value in centered)
    skewness = (
        n_rows / ((n_rows - 1) * (n_rows - 2)) * math.fsum(value**3 for value in standardized)
    )
    excess_kurtosis = n_rows * (n_rows + 1) / (
        (n_rows - 1) * (n_rows - 2) * (n_rows - 3)
    ) * math.fsum(value**4 for value in standardized) - 3.0 * (n_rows - 1) ** 2 / (
        (n_rows - 2) * (n_rows - 3)
    )
    group_values: dict[str, list[float]] = {}
    for group, residual in zip(groups, residuals, strict=True):
        group_values.setdefault(group, []).append(residual)
    group_scales = tuple(
        _sample_scale(tuple(values)) for values in group_values.values() if len(values) >= 2
    )
    positive_group_scales = tuple(
        value for value in group_scales if value > DEGENERATE_SCALE_EPSILON
    )
    has_degenerate_group = len(positive_group_scales) != len(group_scales)
    if len(positive_group_scales) >= 2:
        groupwise_scale_ratio: float | None = max(positive_group_scales) / min(
            positive_group_scales
        )
    else:
        groupwise_scale_ratio = None
    return _ResidualDiagnostics(
        location=location,
        scale=scale,
        skewness=skewness,
        excess_kurtosis=excess_kurtosis,
        groupwise_scale_ratio=groupwise_scale_ratio,
        # A ratio is diagnostically unavailable when fewer than two positive
        # within-group scales exist.  Treat that as material rather than silently
        # allowing the strongest action state.
        groupwise_scale_unbounded=has_degenerate_group or len(positive_group_scales) < 2,
    )


def _sample_scale(values: tuple[float, ...]) -> float:
    location = math.fsum(values) / len(values)
    return math.sqrt(math.fsum((value - location) ** 2 for value in values) / (len(values) - 1))


def _tail_risk_function(
    predictions: tuple[float, ...],
    *,
    lower_limit: float,
    location: float,
    scale: float,
    cdf: Callable[[float], float],
) -> Callable[[float], float]:
    def risk(shift: float) -> float:
        return math.fsum(
            cdf((lower_limit + shift - prediction - location) / scale) for prediction in predictions
        ) / len(predictions)

    return risk


def _solve_maximum_shift(
    risk: Callable[[float], float],
    *,
    alpha: float,
    maximum_shift: float,
) -> _SearchResult:
    baseline_risk = risk(0.0)
    if baseline_risk > alpha:
        return _SearchResult(
            headroom=0.0,
            baseline_risk=baseline_risk,
            terminal_risk=baseline_risk,
            iterations=0,
            right_censored=False,
            baseline_feasible=False,
        )
    maximum_risk = risk(maximum_shift)
    if maximum_risk <= alpha:
        return _SearchResult(
            headroom=maximum_shift,
            baseline_risk=baseline_risk,
            terminal_risk=maximum_risk,
            iterations=0,
            right_censored=True,
            baseline_feasible=True,
        )
    lower = 0.0
    upper = maximum_shift
    iterations = 0
    while upper - lower > BISECTION_TOLERANCE and iterations < BISECTION_MAX_ITERATIONS:
        midpoint = lower + (upper - lower) / 2.0
        if risk(midpoint) <= alpha:
            lower = midpoint
        else:
            upper = midpoint
        iterations += 1
    return _SearchResult(
        headroom=lower,
        baseline_risk=baseline_risk,
        terminal_risk=risk(lower),
        iterations=iterations,
        right_censored=False,
        baseline_feasible=True,
    )


def _standard_normal_cdf(value: float) -> float:
    return 0.5 * (1.0 + math.erf(value / math.sqrt(2.0)))


def _conditional_none() -> Uncertainty:
    return Uncertainty(
        kind=UncertaintyKind.NONE,
        level=None,
        lower=None,
        upper=None,
        conditional_on_selection=True,
    )


def _tail_result(
    *,
    protocol_id: ProtocolId,
    status: ProtocolStatus,
    point_estimate: float | None,
    unit: str,
    metrics: tuple[Metric, ...],
    warnings: tuple[Warning, ...],
    notes: str,
) -> ProtocolComputation:
    return ProtocolComputation(
        protocol_id=protocol_id,
        role=ProtocolRole.HEADROOM,
        status=status,
        point_estimate=point_estimate,
        unit=unit if isinstance(unit, str) and unit else None,
        uncertainty=_conditional_none(),
        metrics=metrics,
        warnings=warnings,
        algorithm_notes=notes,
    )


def _failed_tail_computation(
    protocol_id: ProtocolId,
    unit: str,
    message: str,
) -> ProtocolComputation:
    return _tail_result(
        protocol_id=protocol_id,
        status=ProtocolStatus.FAILED,
        point_estimate=None,
        unit=unit,
        metrics=(),
        warnings=(
            Warning(
                ProtocolReasonCode.PARAMETRIC_INSUFFICIENT_SUPPORT,
                WarningSeverity.BLOCKING,
                message,
            ),
        ),
        notes="Input validation failed closed; no tail result was invented.",
    )


def _ineligible_tail_computation(
    protocol_id: ProtocolId,
    unit: str,
    message: str,
) -> ProtocolComputation:
    return _tail_result(
        protocol_id=protocol_id,
        status=ProtocolStatus.INELIGIBLE,
        point_estimate=None,
        unit=unit,
        metrics=(),
        warnings=(
            Warning(
                ProtocolReasonCode.PARAMETRIC_INSUFFICIENT_SUPPORT,
                WarningSeverity.BLOCKING,
                message,
            ),
        ),
        notes="Residual support was insufficient; no fallback protocol was substituted.",
    )


def _is_finite_number(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value)


__all__ = ["run_gaussian_residual_tail"]
