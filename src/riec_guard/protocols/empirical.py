"""Finite-sample descriptive and strict empirical-tail Fill protocols."""

from __future__ import annotations

import math
from decimal import Decimal, ROUND_FLOOR

from riec_guard.contract.models import (
    ProtocolId,
    ProtocolRole,
    ProtocolStatus,
    WarningSeverity,
)
from riec_guard.protocols.models import (
    Metric,
    ProtocolComputation,
    ProtocolReasonCode,
    Uncertainty,
    Warning,
)


def run_mean_diagnostic(
    quantities: tuple[float, ...],
    *,
    nominal_quantity: float,
    lower_limit: float,
    unit: str,
) -> ProtocolComputation:
    """Return descriptive mean context without treating it as headroom evidence."""

    values = _finite_values(quantities)
    if (
        values is None
        or not values
        or not _is_finite_number(nominal_quantity)
        or not _is_finite_number(lower_limit)
        or not _valid_unit(unit)
    ):
        return _invalid_computation(
            ProtocolId.D0_MEAN_DIAGNOSTIC,
            ProtocolRole.DESCRIPTIVE,
            unit,
            "D0 requires non-empty finite quantities, finite policy values, and a unit.",
        )

    mean_quantity = math.fsum(values) / len(values)
    mean_overfill = mean_quantity - float(nominal_quantity)
    mean_margin = mean_quantity - float(lower_limit)
    underfill_count = sum(value < float(lower_limit) for value in values)
    return ProtocolComputation(
        protocol_id=ProtocolId.D0_MEAN_DIAGNOSTIC,
        role=ProtocolRole.DESCRIPTIVE,
        status=ProtocolStatus.OK,
        point_estimate=mean_overfill,
        unit=unit,
        uncertainty=Uncertainty.none(),
        metrics=(
            Metric("n", len(values)),
            Metric("mean_quantity", mean_quantity, unit),
            Metric("mean_overfill", mean_overfill, unit),
            Metric("mean_margin_above_lower_limit", mean_margin, unit),
            Metric("observed_strict_underfill_count", underfill_count),
            Metric("observed_strict_underfill_rate", underfill_count / len(values), "fraction"),
            Metric("nominal_quantity", float(nominal_quantity), unit),
            Metric("lower_limit", float(lower_limit), unit),
        ),
        warnings=(),
        algorithm_notes=(
            "Arithmetic mean diagnostic only; it is neither a predictive candidate "
            "nor an action-supporting headroom protocol."
        ),
    )


def run_empirical_headroom(
    quantities: tuple[float, ...],
    group_tokens: tuple[str, ...],
    *,
    lower_limit: float,
    alpha: float,
    unit: str,
    min_rows: int,
    min_groups: int,
    min_expected_tail_count: float,
) -> ProtocolComputation:
    """Calculate the exact H1 boundary for ``quantity - shift < lower_limit``.

    The returned point estimate is never rounded to measurement resolution.  That
    policy operation belongs exclusively to action construction.
    """

    values = _finite_values(quantities)
    valid_thresholds = (
        _is_nonnegative_int(min_rows)
        and _is_nonnegative_int(min_groups)
        and _is_finite_number(min_expected_tail_count)
        and float(min_expected_tail_count) >= 0.0
    )
    valid_groups = isinstance(group_tokens, tuple) and all(
        isinstance(token, str) and bool(token) for token in group_tokens
    )
    if (
        values is None
        or not values
        or not valid_groups
        or len(group_tokens) != len(values)
        or not _is_finite_number(lower_limit)
        or not _is_finite_number(alpha)
        or not 0.0 < float(alpha) < 0.5
        or not _valid_unit(unit)
        or not valid_thresholds
    ):
        return _invalid_computation(
            ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE,
            ProtocolRole.HEADROOM,
            unit,
            "H1 inputs violate finite quantity, grouping, alpha, unit, or threshold rules.",
        )

    n_rows = len(values)
    n_groups = len(set(group_tokens))
    # Policy decimals are canonical JSON numbers.  Preserve their declared decimal
    # boundary before taking floor (for example, 0.29 * 100 must be exactly 29).
    expected_tail_decimal = Decimal(str(float(alpha))) * Decimal(n_rows)
    expected_tail_count = float(expected_tail_decimal)
    k = int(expected_tail_decimal.to_integral_value(rounding=ROUND_FLOOR))
    margins = tuple(sorted(value - float(lower_limit) for value in values))
    # Because 0 < alpha < 0.5, k is always in [0, n-1].
    raw_boundary = margins[k]
    headroom = max(0.0, raw_boundary)
    observed_at_raw = sum(margin < raw_boundary for margin in margins)
    observed_at_final = sum(margin < headroom for margin in margins)
    baseline_strict_underfills = sum(margin < 0.0 for margin in margins)
    tie_multiplicity = sum(1 for margin in margins if margin == raw_boundary)

    warnings: list[Warning] = []
    eligibility_blocked = False
    if n_rows < min_rows:
        eligibility_blocked = True
        warnings.append(
            Warning(
                ProtocolReasonCode.EMPIRICAL_INSUFFICIENT_ROWS,
                WarningSeverity.BLOCKING,
                "H1 row support is below the predeclared evidence threshold.",
            )
        )
    if n_groups < min_groups:
        eligibility_blocked = True
        warnings.append(
            Warning(
                ProtocolReasonCode.EMPIRICAL_INSUFFICIENT_GROUPS,
                WarningSeverity.BLOCKING,
                "H1 deployment-group support is below the predeclared threshold.",
            )
        )
    if expected_tail_count < float(min_expected_tail_count):
        eligibility_blocked = True
        warnings.append(
            Warning(
                ProtocolReasonCode.EMPIRICAL_INSUFFICIENT_TAIL_SUPPORT,
                WarningSeverity.BLOCKING,
                "H1 expected tail count is below the predeclared evidence threshold.",
            )
        )
    if baseline_strict_underfills > k:
        eligibility_blocked = True
        warnings.append(
            Warning(
                ProtocolReasonCode.EMPIRICAL_BASELINE_EXCEEDS_TAIL_LIMIT,
                WarningSeverity.MATERIAL,
                "The unshifted data already exceed the permitted empirical strict-tail count.",
            )
        )
    if tie_multiplicity > 1:
        warnings.append(
            Warning(
                ProtocolReasonCode.EMPIRICAL_BOUNDARY_TIE,
                WarningSeverity.WARNING,
                "Multiple margins equal the closed H1 boundary; positive movement beyond it "
                "can cross several observations at once.",
            )
        )

    status = (
        ProtocolStatus.INELIGIBLE
        if eligibility_blocked
        else ProtocolStatus.WARNING
        if warnings
        else ProtocolStatus.OK
    )
    return ProtocolComputation(
        protocol_id=ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE,
        role=ProtocolRole.HEADROOM,
        status=status,
        point_estimate=headroom,
        unit=unit,
        uncertainty=Uncertainty.none(),
        metrics=(
            Metric("n", n_rows),
            Metric("n_groups", n_groups),
            Metric("alpha", float(alpha)),
            Metric("expected_tail_count", expected_tail_count),
            Metric("minimum_expected_tail_count", float(min_expected_tail_count)),
            Metric("k_floor_alpha_n", k),
            Metric("order_statistic_index_one_based", k + 1),
            Metric("raw_boundary", raw_boundary, unit),
            Metric("boundary_tie_multiplicity", tie_multiplicity),
            Metric("strict_underfills_at_raw_boundary", observed_at_raw),
            Metric("strict_underfills_at_final_headroom", observed_at_final),
            Metric("baseline_strict_underfills", baseline_strict_underfills),
        ),
        warnings=tuple(warnings),
        algorithm_notes=(
            "Exact finite-sample boundary m_(floor(alpha*n)+1) for the strict event "
            "quantity - reduction < lower_limit; clamped at zero without resolution rounding."
        ),
    )


def _invalid_computation(
    protocol_id: ProtocolId,
    role: ProtocolRole,
    unit: str,
    message: str,
) -> ProtocolComputation:
    return ProtocolComputation(
        protocol_id=protocol_id,
        role=role,
        status=ProtocolStatus.FAILED,
        point_estimate=None,
        unit=unit if _valid_unit(unit) else None,
        uncertainty=Uncertainty.none(),
        metrics=(),
        warnings=(
            Warning(
                ProtocolReasonCode.EMPIRICAL_INVALID_INPUT,
                WarningSeverity.BLOCKING,
                message,
            ),
        ),
        algorithm_notes="Input validation failed closed; no numerical result was invented.",
    )


def _finite_values(values: tuple[float, ...]) -> tuple[float, ...] | None:
    if not isinstance(values, tuple):
        return None
    if any(not _is_finite_number(value) for value in values):
        return None
    return tuple(float(value) for value in values)


def _is_finite_number(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value)


def _is_nonnegative_int(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 0


def _valid_unit(unit: object) -> bool:
    return isinstance(unit, str) and 0 < len(unit) <= 32


__all__ = ["run_empirical_headroom", "run_mean_diagnostic"]
