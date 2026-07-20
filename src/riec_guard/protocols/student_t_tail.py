"""Bounded Student-t residual-tail Fill protocol."""

from __future__ import annotations

import math
import statistics
import time
from dataclasses import dataclass

import numpy as np
import numpy.typing as npt
from scipy import optimize, stats  # type: ignore[import-untyped]

from riec_guard.contract.models import ProtocolId, ProtocolStatus, WarningSeverity
from riec_guard.protocols.gaussian_tail import (
    _ineligible_tail_computation,
    _is_finite_number,
    _residual_diagnostics,
    _solve_maximum_shift,
    _tail_result,
    _validate_tail_inputs,
)
from riec_guard.protocols.models import (
    CrossFittedPrediction,
    Metric,
    ProtocolComputation,
    ProtocolReasonCode,
    Warning,
)

MINIMUM_DF = 2.1
MAXIMUM_DF = 100.0
DF_BOUNDARY_TOLERANCE = 1.0e-3
FIT_MAXIMUM_ITERATIONS = 500
FIT_MAXIMUM_EVALUATIONS = 1500
MAXIMUM_FIT_TIMEOUT_SECONDS = 3.0
STUDENT_T_ESTIMATOR_VERSION = "bounded-mle-lbfgsb.v1"


class _FitTimedOut(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class _StudentFit:
    df: float
    location: float
    scale: float
    objective: float
    iterations: int


@dataclass(frozen=True, slots=True)
class _FitOutcome:
    fit: _StudentFit | None
    failure_code: ProtocolReasonCode | None


def run_student_t_residual_tail(
    quantities: tuple[float, ...],
    group_tokens: tuple[str, ...],
    cross_fitted: tuple[CrossFittedPrediction, ...],
    *,
    lower_limit: float,
    alpha: float,
    maximum_screening_shift: float,
    unit: str,
    fit_timeout_seconds: float = 3.0,
) -> ProtocolComputation:
    """Fit bounded Student-t residual models and conservatively aggregate them."""

    validated = _validate_tail_inputs(
        quantities,
        group_tokens,
        cross_fitted,
        lower_limit=lower_limit,
        alpha=alpha,
        maximum_screening_shift=maximum_screening_shift,
        unit=unit,
    )
    if (
        validated is None
        or not _is_finite_number(fit_timeout_seconds)
        or float(fit_timeout_seconds) <= 0.0
        or float(fit_timeout_seconds) > MAXIMUM_FIT_TIMEOUT_SECONDS
    ):
        return _ineligible_tail_computation(
            ProtocolId.H3_STUDENT_T_RESIDUAL_TAIL,
            unit,
            "H3 requires finite aligned inputs and a fit timeout in (0, 3] seconds.",
        )
    values, groups, models = validated
    if len(values) < 4 or len(set(groups)) < 2:
        return _ineligible_tail_computation(
            ProtocolId.H3_STUDENT_T_RESIDUAL_TAIL,
            unit,
            "H3 needs at least four residuals across at least two deployment groups.",
        )

    fits: list[_StudentFit] = []
    searches = []
    diagnostics = []
    eligible_candidate_ids: list[str] = []
    failure_codes: list[ProtocolReasonCode] = []
    for model in models:
        residuals = tuple(
            observed - predicted
            for observed, predicted in zip(values, model.predictions, strict=True)
        )
        candidate_diagnostics = _residual_diagnostics(residuals, groups)
        if candidate_diagnostics is None:
            failure_codes.append(ProtocolReasonCode.PARAMETRIC_DEGENERATE_SCALE)
            continue
        outcome = _fit_student_t(
            residuals,
            initial_location=candidate_diagnostics.location,
            initial_scale=candidate_diagnostics.scale,
            timeout_seconds=float(fit_timeout_seconds),
        )
        if outcome.fit is None:
            assert outcome.failure_code is not None
            failure_codes.append(outcome.failure_code)
            continue
        fit = outcome.fit
        risk = _student_tail_risk(
            model.predictions,
            lower_limit=float(lower_limit),
            fit=fit,
        )
        search = _solve_maximum_shift(
            risk,
            alpha=float(alpha),
            maximum_shift=float(maximum_screening_shift),
        )
        fits.append(fit)
        searches.append(search)
        diagnostics.append(candidate_diagnostics)
        eligible_candidate_ids.append(model.candidate_id)

    warnings = _fit_warnings(failure_codes)
    if not searches:
        warnings.append(
            Warning(
                ProtocolReasonCode.PARAMETRIC_INSUFFICIENT_SUPPORT,
                WarningSeverity.BLOCKING,
                "No Student-t equivalence-set member produced an eligible bounded fit.",
            )
        )
        return _tail_result(
            protocol_id=ProtocolId.H3_STUDENT_T_RESIDUAL_TAIL,
            status=ProtocolStatus.INELIGIBLE,
            point_estimate=None,
            unit=unit,
            metrics=(
                Metric("n", len(values)),
                Metric("n_groups", len(set(groups))),
                Metric("candidate_count_requested", len(models)),
                Metric("candidate_count_eligible", 0),
                Metric("candidate_fit_failure_count", len(failure_codes)),
                Metric(
                    "fit_failure_codes",
                    ",".join(sorted({code.value for code in failure_codes})),
                ),
                Metric("student_t_estimator", STUDENT_T_ESTIMATOR_VERSION),
                Metric("fit_timeout_seconds", float(fit_timeout_seconds), "s"),
            ),
            warnings=tuple(warnings),
            notes=(
                "Bounded Student-t maximum-likelihood fit failed closed; no Gaussian "
                "or empirical result was substituted under the H3 identity."
            ),
        )

    baseline_infeasible_count = sum(not search.baseline_feasible for search in searches)
    right_censored_count = sum(search.right_censored for search in searches)
    if baseline_infeasible_count:
        warnings.append(
            Warning(
                ProtocolReasonCode.PARAMETRIC_INSUFFICIENT_SUPPORT,
                WarningSeverity.MATERIAL,
                "At least one fitted Student-t model exceeds alpha before any reduction; "
                "its headroom is zero.",
            )
        )
    if right_censored_count:
        warnings.append(
            Warning(
                ProtocolReasonCode.PARAMETRIC_SEARCH_CENSORED,
                WarningSeverity.WARNING,
                "At least one Student-t headroom remains feasible at the predeclared search "
                "maximum and is reported as right-censored there.",
            )
        )

    headrooms = tuple(search.headroom for search in searches)
    fitted_dfs = tuple(fit.df for fit in fits)
    fitted_locations = tuple(fit.location for fit in fits)
    fitted_scales = tuple(fit.scale for fit in fits)
    status = ProtocolStatus.WARNING if warnings else ProtocolStatus.OK
    return _tail_result(
        protocol_id=ProtocolId.H3_STUDENT_T_RESIDUAL_TAIL,
        status=status,
        point_estimate=min(headrooms),
        unit=unit,
        metrics=(
            Metric("n", len(values)),
            Metric("n_groups", len(set(groups))),
            Metric("alpha", float(alpha)),
            Metric("candidate_count_requested", len(models)),
            Metric("candidate_count_eligible", len(fits)),
            Metric("eligible_candidate_ids", ",".join(eligible_candidate_ids)),
            Metric("candidate_headrooms", headrooms, unit),
            Metric("fitted_df_values", fitted_dfs),
            Metric("fitted_df_min", min(fitted_dfs)),
            Metric("fitted_df_max", max(fitted_dfs)),
            Metric("fitted_location_min", min(fitted_locations), unit),
            Metric("fitted_location_max", max(fitted_locations), unit),
            Metric("fitted_scale_min", min(fitted_scales), unit),
            Metric("fitted_scale_max", max(fitted_scales), unit),
            Metric("optimizer_objective_max", max(fit.objective for fit in fits)),
            Metric("optimizer_iterations_max", max(fit.iterations for fit in fits)),
            Metric(
                "residual_skewness_max_abs",
                max(abs(item.skewness) for item in diagnostics),
            ),
            Metric(
                "residual_excess_kurtosis_max",
                max(item.excess_kurtosis for item in diagnostics),
            ),
            Metric("baseline_tail_risk_max", max(item.baseline_risk for item in searches)),
            Metric("terminal_tail_risk_max", max(item.terminal_risk for item in searches)),
            Metric("baseline_infeasible_count", baseline_infeasible_count),
            Metric("right_censored_count", right_censored_count),
            Metric("candidate_fit_failure_count", len(failure_codes)),
            Metric(
                "fit_failure_codes",
                ",".join(sorted({code.value for code in failure_codes})),
            ),
            Metric("search_lower_bound", 0.0, unit),
            Metric("search_upper_bound", float(maximum_screening_shift), unit),
            Metric("student_t_estimator", STUDENT_T_ESTIMATOR_VERSION),
            Metric("minimum_df", MINIMUM_DF),
            Metric("maximum_df", MAXIMUM_DF),
            Metric("df_boundary_tolerance", DF_BOUNDARY_TOLERANCE),
            Metric("fit_timeout_seconds", float(fit_timeout_seconds), "s"),
        ),
        warnings=tuple(warnings),
        notes=(
            "Cross-fitted Student-t residual-tail risk using bounded maximum likelihood "
            "(2.1 <= df <= 100), bounded fit time, deterministic bisection, and minimum "
            "aggregation across the frozen equivalence set."
        ),
    )


def _fit_student_t(
    residuals: tuple[float, ...],
    *,
    initial_location: float,
    initial_scale: float,
    timeout_seconds: float,
) -> _FitOutcome:
    started = time.monotonic()
    observations = np.asarray(residuals, dtype=np.float64)
    location_radius = max(10.0 * initial_scale, 1.0)
    location_lower = min(residuals) - location_radius
    location_upper = max(residuals) + location_radius
    scale_lower = max(initial_scale * 1.0e-4, 1.0e-12)
    scale_upper = max(initial_scale * 100.0, scale_lower * 10.0)
    bounds = (
        (MINIMUM_DF, MAXIMUM_DF),
        (location_lower, location_upper),
        (math.log(scale_lower), math.log(scale_upper)),
    )
    initial = np.asarray(
        (10.0, float(statistics.median(residuals)), math.log(initial_scale)),
        dtype=np.float64,
    )

    def check_timeout() -> None:
        if time.monotonic() - started >= timeout_seconds:
            raise _FitTimedOut

    def objective(parameters: npt.NDArray[np.float64]) -> float:
        check_timeout()
        df, location, log_scale = (float(value) for value in parameters)
        scale = math.exp(log_scale)
        log_density = stats.t.logpdf(
            observations,
            df=df,
            loc=location,
            scale=scale,
        )
        if not np.isfinite(log_density).all():
            return float(np.finfo(np.float64).max / 100.0)
        return -float(np.sum(log_density, dtype=np.float64))

    def callback(_: npt.NDArray[np.float64]) -> None:
        check_timeout()

    try:
        check_timeout()
        result = optimize.minimize(
            objective,
            initial,
            method="L-BFGS-B",
            bounds=bounds,
            callback=callback,
            options={
                "maxiter": FIT_MAXIMUM_ITERATIONS,
                "maxfun": FIT_MAXIMUM_EVALUATIONS,
                "ftol": 1.0e-12,
            },
        )
        check_timeout()
    except _FitTimedOut:
        return _FitOutcome(None, ProtocolReasonCode.STUDENT_T_FIT_TIMEOUT)
    except (ArithmeticError, FloatingPointError, ValueError):
        return _FitOutcome(None, ProtocolReasonCode.STUDENT_T_FIT_NONCONVERGENCE)

    if not result.success or result.x.shape != (3,) or not np.isfinite(result.x).all():
        return _FitOutcome(None, ProtocolReasonCode.STUDENT_T_FIT_NONCONVERGENCE)
    df, location, log_scale = (float(value) for value in result.x)
    scale = math.exp(log_scale)
    if not math.isfinite(scale) or scale <= 1.0e-12:
        return _FitOutcome(None, ProtocolReasonCode.PARAMETRIC_DEGENERATE_SCALE)
    if (
        abs(df - MINIMUM_DF) <= DF_BOUNDARY_TOLERANCE
        or abs(df - MAXIMUM_DF) <= DF_BOUNDARY_TOLERANCE
    ):
        return _FitOutcome(None, ProtocolReasonCode.STUDENT_T_DF_BOUNDARY)
    objective_value = float(result.fun)
    if not all(math.isfinite(value) for value in (df, location, scale, objective_value)):
        return _FitOutcome(None, ProtocolReasonCode.STUDENT_T_FIT_NONCONVERGENCE)
    return _FitOutcome(
        _StudentFit(
            df=df,
            location=location,
            scale=scale,
            objective=objective_value,
            iterations=int(result.nit),
        ),
        None,
    )


def _student_tail_risk(
    predictions: tuple[float, ...],
    *,
    lower_limit: float,
    fit: _StudentFit,
):
    def risk(shift: float) -> float:
        return math.fsum(
            float(
                stats.t.cdf(
                    (lower_limit + shift - prediction - fit.location) / fit.scale,
                    df=fit.df,
                )
            )
            for prediction in predictions
        ) / len(predictions)

    return risk


def _fit_warnings(failure_codes: list[ProtocolReasonCode]) -> list[Warning]:
    messages = {
        ProtocolReasonCode.PARAMETRIC_DEGENERATE_SCALE: (
            "One or more Student-t residual fits had degenerate scale and were excluded."
        ),
        ProtocolReasonCode.STUDENT_T_FIT_TIMEOUT: (
            "One or more Student-t fits exceeded the predeclared per-fit time limit."
        ),
        ProtocolReasonCode.STUDENT_T_FIT_NONCONVERGENCE: (
            "One or more bounded Student-t fits did not converge."
        ),
        ProtocolReasonCode.STUDENT_T_DF_BOUNDARY: (
            "One or more Student-t fits pinned degrees of freedom at a declared boundary."
        ),
    }
    return [
        Warning(code, WarningSeverity.MATERIAL, messages[code])
        for code in sorted(set(failure_codes), key=lambda item: item.value)
    ]


__all__ = ["run_student_t_residual_tail"]
