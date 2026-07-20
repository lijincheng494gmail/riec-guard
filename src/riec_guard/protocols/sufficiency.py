"""G2 evidence-sufficiency gate with explicit configurable thresholds."""

from __future__ import annotations

import math
from decimal import Decimal

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
    SufficiencySummary,
    Uncertainty,
    Warning,
)


def run_evidence_sufficiency_gate(
    *,
    n_rows: int,
    n_groups: int,
    alpha: float,
    min_rows: int,
    min_groups_exploratory: int,
    min_groups_action: int,
    min_expected_tail_count: float,
    bootstrap_valid: bool,
    ordered_required: bool,
    ordered_coverage: float | None,
    min_ordered_coverage: float,
    measurement_valid: bool,
    product_support: tuple[tuple[int, int], ...] | None = None,
) -> SufficiencySummary:
    """Separate exploratory support from stricter action-level support."""

    _validate_inputs(
        n_rows=n_rows,
        n_groups=n_groups,
        alpha=alpha,
        min_rows=min_rows,
        min_groups_exploratory=min_groups_exploratory,
        min_groups_action=min_groups_action,
        min_expected_tail_count=min_expected_tail_count,
        bootstrap_valid=bootstrap_valid,
        ordered_required=ordered_required,
        ordered_coverage=ordered_coverage,
        min_ordered_coverage=min_ordered_coverage,
        measurement_valid=measurement_valid,
        product_support=product_support,
    )
    support = product_support or ((n_rows, n_groups),)
    minimum_product_rows = min(rows for rows, _ in support)
    minimum_product_groups = min(groups for _, groups in support)
    expected_tail_count = float(Decimal(str(alpha)) * Decimal(minimum_product_rows))
    reasons: list[ProtocolReasonCode] = []
    if minimum_product_rows < min_rows:
        reasons.append(ProtocolReasonCode.EVIDENCE_ROWS_INSUFFICIENT)
    if minimum_product_groups < min_groups_exploratory:
        reasons.append(ProtocolReasonCode.EVIDENCE_GROUPS_EXPLORATORY_INSUFFICIENT)
    if minimum_product_groups < min_groups_action:
        reasons.append(ProtocolReasonCode.EVIDENCE_GROUPS_ACTION_INSUFFICIENT)
    if expected_tail_count < min_expected_tail_count:
        reasons.append(ProtocolReasonCode.EVIDENCE_TAIL_SUPPORT_INSUFFICIENT)
    if not bootstrap_valid:
        reasons.append(ProtocolReasonCode.EVIDENCE_BOOTSTRAP_INSUFFICIENT)
    if ordered_required and (ordered_coverage is None or ordered_coverage < min_ordered_coverage):
        reasons.append(ProtocolReasonCode.EVIDENCE_ORDER_INSUFFICIENT)
    if not measurement_valid:
        reasons.append(ProtocolReasonCode.EVIDENCE_MEASUREMENT_INSUFFICIENT)

    # The frozen profile's row minimum is action-level.  Exploratory grouped RIEC
    # support is governed by the exploratory group threshold and valid measurement.
    exploratory_supported = minimum_product_groups >= min_groups_exploratory and measurement_valid
    action_supported = (
        exploratory_supported
        and minimum_product_rows >= min_rows
        and minimum_product_groups >= min_groups_action
        and expected_tail_count >= min_expected_tail_count
        and bootstrap_valid
        and (
            not ordered_required
            or ordered_coverage is not None
            and ordered_coverage >= min_ordered_coverage
        )
    )
    warnings = tuple(
        Warning(
            code=reason,
            severity=WarningSeverity.BLOCKING,
            message=_REASON_MESSAGES[reason],
        )
        for reason in reasons
    )
    computation = ProtocolComputation(
        protocol_id=ProtocolId.G2_EVIDENCE_SUFFICIENCY_GATE,
        role=ProtocolRole.EVIDENCE_GATE,
        status=ProtocolStatus.OK if action_supported else ProtocolStatus.INELIGIBLE,
        point_estimate=None,
        unit=None,
        uncertainty=Uncertainty.none(),
        metrics=(
            Metric("n_rows", n_rows),
            Metric("n_groups", n_groups),
            Metric("product_scope_count", len(support)),
            Metric("minimum_product_rows", minimum_product_rows),
            Metric("minimum_product_groups", minimum_product_groups),
            Metric("alpha", alpha),
            Metric("expected_tail_count", expected_tail_count),
            Metric("min_rows", min_rows),
            Metric("min_groups_exploratory", min_groups_exploratory),
            Metric("min_groups_action", min_groups_action),
            Metric("min_expected_tail_count", min_expected_tail_count),
            Metric("bootstrap_valid", bootstrap_valid),
            Metric("ordered_required", ordered_required),
            Metric("ordered_coverage", ordered_coverage),
            Metric("min_ordered_coverage", min_ordered_coverage),
            Metric("measurement_valid", measurement_valid),
            Metric("exploratory_supported", exploratory_supported),
            Metric("action_supported", action_supported),
        ),
        warnings=warnings,
        algorithm_notes=(
            "G2 checks configured row, deployment-group, expected-tail, bootstrap, ordered "
            "coverage, and measurement support. It does not calculate headroom."
        ),
    )
    return SufficiencySummary(
        computation=computation,
        exploratory_supported=exploratory_supported,
        action_supported=action_supported,
        reason_codes=tuple(reasons),
    )


_REASON_MESSAGES = {
    ProtocolReasonCode.EVIDENCE_ROWS_INSUFFICIENT: (
        "Row count is below the configured evidence threshold."
    ),
    ProtocolReasonCode.EVIDENCE_GROUPS_EXPLORATORY_INSUFFICIENT: (
        "Deployment-group count is below the exploratory RIEC threshold."
    ),
    ProtocolReasonCode.EVIDENCE_GROUPS_ACTION_INSUFFICIENT: (
        "Deployment-group count is below the action-support threshold."
    ),
    ProtocolReasonCode.EVIDENCE_TAIL_SUPPORT_INSUFFICIENT: (
        "Expected tail count is below the configured action threshold."
    ),
    ProtocolReasonCode.EVIDENCE_BOOTSTRAP_INSUFFICIENT: (
        "A valid whole-group bootstrap result is unavailable."
    ),
    ProtocolReasonCode.EVIDENCE_ORDER_INSUFFICIENT: (
        "Required ordered-stream coverage is below the configured threshold."
    ),
    ProtocolReasonCode.EVIDENCE_MEASUREMENT_INSUFFICIENT: (
        "Measurement or conversion support is invalid for action interpretation."
    ),
}


def _validate_inputs(
    *,
    n_rows: int,
    n_groups: int,
    alpha: float,
    min_rows: int,
    min_groups_exploratory: int,
    min_groups_action: int,
    min_expected_tail_count: float,
    bootstrap_valid: bool,
    ordered_required: bool,
    ordered_coverage: float | None,
    min_ordered_coverage: float,
    measurement_valid: bool,
    product_support: tuple[tuple[int, int], ...] | None,
) -> None:
    integer_values = (n_rows, n_groups, min_rows, min_groups_exploratory, min_groups_action)
    if any(isinstance(value, bool) for value in integer_values):
        raise ValueError("evidence counts and thresholds must be integers")
    if n_rows < 0 or n_groups < 0 or min_rows < 1 or min_groups_exploratory < 2:
        raise ValueError("evidence counts or thresholds are outside their valid domain")
    if min_groups_action < min_groups_exploratory:
        raise ValueError("min_groups_action must not be below min_groups_exploratory")
    if any(
        type(value) is not bool for value in (bootstrap_valid, ordered_required, measurement_valid)
    ):
        raise ValueError("evidence gate flags must be booleans")
    if not math.isfinite(alpha) or not 0.0 < alpha < 0.5:
        raise ValueError("alpha must be finite and between zero and 0.5")
    if not math.isfinite(min_expected_tail_count) or min_expected_tail_count < 1.0:
        raise ValueError("min_expected_tail_count must be finite and at least one")
    if not math.isfinite(min_ordered_coverage) or not 0.0 <= min_ordered_coverage <= 1.0:
        raise ValueError("min_ordered_coverage must be between zero and one")
    if ordered_coverage is not None and (
        not math.isfinite(ordered_coverage) or not 0.0 <= ordered_coverage <= 1.0
    ):
        raise ValueError("ordered_coverage must be null or between zero and one")
    if product_support is not None:
        if not isinstance(product_support, tuple) or not product_support:
            raise ValueError("product_support must be a non-empty tuple when supplied")
        for item in product_support:
            if (
                not isinstance(item, tuple)
                or len(item) != 2
                or any(not isinstance(value, int) or isinstance(value, bool) for value in item)
                or item[0] < 0
                or item[1] < 0
                or item[1] > n_groups
            ):
                raise ValueError("product support counts are invalid")
        if sum(rows for rows, _ in product_support) != n_rows:
            raise ValueError("product row counts must partition the dataset")


__all__ = ["run_evidence_sufficiency_gate"]
