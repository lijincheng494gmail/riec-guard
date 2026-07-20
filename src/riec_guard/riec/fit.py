"""Deterministic ordinary-least-squares fitting for the grouped RIEC-L1 core."""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
import numpy.typing as npt


@dataclass(frozen=True, slots=True)
class FitFailure(ValueError):
    """Fail-closed OLS error carrying a stable, non-sensitive reason code."""

    code: str


@dataclass(frozen=True, slots=True)
class OlsFitResult:
    """Immutable full-data OLS result with the RIEC-L1 information criteria."""

    coefficients: tuple[float, ...]
    n_rows: int
    n_columns: int
    realized_rank: int
    residual_degrees_freedom: int
    rss: float
    aic: float
    aicc: float | None
    bic_eff: float
    singular_tolerance: float


@dataclass(frozen=True, slots=True)
class LinearFitResult:
    """OLS coefficients and diagnostics without information-criterion logarithms."""

    coefficients: tuple[float, ...]
    n_rows: int
    n_columns: int
    realized_rank: int
    residual_degrees_freedom: int
    rss: float
    singular_tolerance: float


def fit_ols(
    design: tuple[tuple[float, ...], ...],
    response: tuple[float, ...],
    *,
    n_eff: int,
) -> OlsFitResult:
    """Fit full-rank OLS and calculate the frozen RIEC-L1 structural signals.

    The explicit ``rcond`` supplied to ``numpy.linalg.lstsq`` is
    ``eps * max(n_rows, n_columns)``. A structurally rank-deficient design is a
    failure; columns are never silently removed under the same candidate ID.
    """

    if isinstance(n_eff, bool) or not isinstance(n_eff, int) or n_eff <= 1:
        raise FitFailure("FIT_INVALID_N_EFF")
    linear = fit_linear_model(design, response)
    if linear.rss <= 0.0:
        raise FitFailure("CANDIDATE_ZERO_RSS")

    # Frozen equations:
    # AIC = n * log(RSS / n) + 2k
    # AICc = AIC + 2k(k + 1) / (n - k - 1), when n > k + 1
    # BIC_eff = n_eff * log(RSS / n_eff) + k * log(n_eff)
    k_eff = linear.realized_rank
    if n_eff != linear.n_rows:
        raise FitFailure("FIT_INVALID_N_EFF")
    try:
        # The log difference is algebraically identical to log(RSS / n) but
        # avoids a spurious zero when two positive finite values underflow on division.
        log_mean_rss = math.log(linear.rss) - math.log(linear.n_rows)
        aic = linear.n_rows * log_mean_rss + 2.0 * k_eff
        aicc = (
            aic + (2.0 * k_eff * (k_eff + 1)) / (linear.n_rows - k_eff - 1)
            if linear.n_rows > k_eff + 1
            else None
        )
        bic_eff = n_eff * (math.log(linear.rss) - math.log(n_eff)) + k_eff * math.log(n_eff)
    except ArithmeticError as error:
        raise FitFailure("CANDIDATE_NONFINITE_RESULT") from error
    if not math.isfinite(aic) or (aicc is not None and not math.isfinite(aicc)):
        raise FitFailure("CANDIDATE_NONFINITE_RESULT")
    if not math.isfinite(bic_eff):
        raise FitFailure("CANDIDATE_NONFINITE_RESULT")

    return OlsFitResult(
        coefficients=linear.coefficients,
        n_rows=linear.n_rows,
        n_columns=linear.n_columns,
        realized_rank=linear.realized_rank,
        residual_degrees_freedom=linear.residual_degrees_freedom,
        rss=linear.rss,
        aic=aic,
        aicc=aicc,
        bic_eff=bic_eff,
        singular_tolerance=linear.singular_tolerance,
    )


def fit_linear_model(
    design: tuple[tuple[float, ...], ...],
    response: tuple[float, ...],
) -> LinearFitResult:
    """Fit full-rank OLS for prediction; an exact zero training RSS is valid."""

    matrix = _as_design_matrix(design, code="FIT_INVALID_DESIGN")
    target = _as_response_vector(response)
    n_rows, n_columns = matrix.shape
    if target.shape[0] != n_rows:
        raise FitFailure("FIT_RESPONSE_LENGTH_MISMATCH")
    if not np.isfinite(matrix).all() or not np.isfinite(target).all():
        raise FitFailure("FIT_NONFINITE_INPUT")
    singular_tolerance = float(np.finfo(np.float64).eps * max(n_rows, n_columns))
    try:
        coefficients, _, realized_rank, _ = np.linalg.lstsq(
            matrix,
            target,
            rcond=singular_tolerance,
        )
    except np.linalg.LinAlgError as error:
        raise FitFailure("CANDIDATE_FIT_FAILED") from error
    rank = int(realized_rank)
    if rank < n_columns:
        raise FitFailure("CANDIDATE_DESIGN_RANK_DEFICIENT")
    if not np.isfinite(coefficients).all():
        raise FitFailure("CANDIDATE_NONFINITE_RESULT")
    predictions = matrix @ coefficients
    if not np.isfinite(predictions).all():
        raise FitFailure("CANDIDATE_NONFINITE_RESULT")
    try:
        rss = math.fsum(float(residual) ** 2 for residual in target - predictions)
    except ArithmeticError as error:
        raise FitFailure("CANDIDATE_NONFINITE_RESULT") from error
    if not math.isfinite(rss) or rss < 0.0:
        raise FitFailure("CANDIDATE_NONFINITE_RESULT")
    return LinearFitResult(
        coefficients=tuple(float(value) for value in coefficients),
        n_rows=n_rows,
        n_columns=n_columns,
        realized_rank=rank,
        residual_degrees_freedom=n_rows - rank,
        rss=rss,
        singular_tolerance=singular_tolerance,
    )


def predict_ols(
    fit: OlsFitResult | LinearFitResult,
    design: tuple[tuple[float, ...], ...],
) -> tuple[float, ...]:
    """Predict with an immutable OLS fit, rejecting malformed or non-finite input."""

    matrix = _as_design_matrix(design, code="PREDICT_INVALID_DESIGN")
    if matrix.shape[1] != fit.n_columns:
        raise FitFailure("PREDICT_COLUMN_MISMATCH")
    if not np.isfinite(matrix).all():
        raise FitFailure("PREDICT_NONFINITE_INPUT")

    predictions = matrix @ np.asarray(fit.coefficients, dtype=np.float64)
    if not np.isfinite(predictions).all():
        raise FitFailure("CANDIDATE_NONFINITE_RESULT")
    return tuple(float(value) for value in predictions)


def _as_design_matrix(
    design: tuple[tuple[float, ...], ...],
    *,
    code: str,
) -> npt.NDArray[np.float64]:
    try:
        matrix = np.asarray(design, dtype=np.float64)
    except (TypeError, ValueError) as error:
        raise FitFailure(code) from error
    if matrix.ndim != 2 or matrix.shape[0] == 0 or matrix.shape[1] == 0:
        raise FitFailure(code)
    return matrix


def _as_response_vector(response: tuple[float, ...]) -> npt.NDArray[np.float64]:
    try:
        target = np.asarray(response, dtype=np.float64)
    except (TypeError, ValueError) as error:
        raise FitFailure("FIT_INVALID_RESPONSE") from error
    if target.ndim != 1 or target.shape[0] == 0:
        raise FitFailure("FIT_INVALID_RESPONSE")
    return target
