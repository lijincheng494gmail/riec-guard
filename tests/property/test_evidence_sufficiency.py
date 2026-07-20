from __future__ import annotations

import pytest

from riec_guard.contract.models import ProtocolStatus
from riec_guard.protocols.models import ProtocolReasonCode
from riec_guard.protocols.sufficiency import run_evidence_sufficiency_gate


def _run(**changes: object):
    values: dict[str, object] = {
        "n_rows": 500,
        "n_groups": 8,
        "alpha": 0.01,
        "min_rows": 80,
        "min_groups_exploratory": 4,
        "min_groups_action": 8,
        "min_expected_tail_count": 5.0,
        "bootstrap_valid": True,
        "ordered_required": True,
        "ordered_coverage": 0.6,
        "min_ordered_coverage": 0.6,
        "measurement_valid": True,
    }
    values.update(changes)
    return run_evidence_sufficiency_gate(**values)  # type: ignore[arg-type]


def test_default_threshold_boundary_supports_action() -> None:
    result = _run()

    assert result.exploratory_supported
    assert result.action_supported
    assert result.reason_codes == ()
    assert result.computation.status is ProtocolStatus.OK
    assert result.computation.point_estimate is None


@pytest.mark.parametrize("n_groups", [0, 1, 2, 3])
def test_fewer_than_four_groups_blocks_riec_exploration(n_groups: int) -> None:
    result = _run(n_groups=n_groups)

    assert not result.exploratory_supported
    assert not result.action_supported
    assert ProtocolReasonCode.EVIDENCE_GROUPS_EXPLORATORY_INSUFFICIENT in result.reason_codes


@pytest.mark.parametrize("n_groups", [4, 5, 6, 7])
def test_fewer_than_eight_groups_allows_exploration_but_blocks_action(n_groups: int) -> None:
    result = _run(n_groups=n_groups)

    assert result.exploratory_supported
    assert not result.action_supported
    assert ProtocolReasonCode.EVIDENCE_GROUPS_ACTION_INSUFFICIENT in result.reason_codes
    assert result.computation.status is ProtocolStatus.INELIGIBLE


def test_expected_tail_count_below_five_is_explicit() -> None:
    result = _run(n_rows=499)

    assert not result.action_supported
    assert ProtocolReasonCode.EVIDENCE_TAIL_SUPPORT_INSUFFICIENT in result.reason_codes
    assert result.computation.metric("expected_tail_count") == pytest.approx(4.99)


def test_decimal_expected_tail_boundary_is_not_falsely_ineligible() -> None:
    result = _run(
        n_rows=100,
        alpha=0.29,
        min_rows=100,
        min_expected_tail_count=29.0,
    )

    assert result.action_supported
    assert result.computation.metric("expected_tail_count") == 29.0


def test_action_row_minimum_does_not_erase_exploratory_group_support() -> None:
    result = _run(n_rows=79, n_groups=4, alpha=0.1)

    assert result.exploratory_supported
    assert not result.action_supported
    assert ProtocolReasonCode.EVIDENCE_ROWS_INSUFFICIENT in result.reason_codes


def test_per_product_support_cannot_be_hidden_by_global_totals() -> None:
    result = _run(
        n_rows=160,
        n_groups=8,
        alpha=0.1,
        product_support=((150, 8), (10, 2)),
    )

    assert not result.exploratory_supported
    assert not result.action_supported
    assert result.computation.metric("product_scope_count") == 2
    assert result.computation.metric("minimum_product_rows") == 10
    assert result.computation.metric("minimum_product_groups") == 2
    assert ProtocolReasonCode.EVIDENCE_GROUPS_EXPLORATORY_INSUFFICIENT in result.reason_codes


def test_order_is_checked_only_when_policy_requires_it() -> None:
    required = _run(ordered_coverage=None)
    optional = _run(ordered_required=False, ordered_coverage=None)

    assert not required.action_supported
    assert ProtocolReasonCode.EVIDENCE_ORDER_INSUFFICIENT in required.reason_codes
    assert optional.action_supported


def test_thresholds_are_configurable_and_retained_as_metrics() -> None:
    result = _run(
        n_rows=10,
        n_groups=6,
        alpha=0.1,
        min_rows=10,
        min_groups_exploratory=2,
        min_groups_action=6,
        min_expected_tail_count=1.0,
        ordered_required=False,
    )

    assert result.action_supported
    assert result.computation.metric("min_rows") == 10
    assert result.computation.metric("min_groups_exploratory") == 2
    assert result.computation.metric("min_groups_action") == 6
    assert result.computation.metric("min_expected_tail_count") == 1.0


def test_bootstrap_and_measurement_failures_are_blocking_and_named() -> None:
    result = _run(bootstrap_valid=False, measurement_valid=False)

    assert not result.exploratory_supported
    assert not result.action_supported
    assert ProtocolReasonCode.EVIDENCE_BOOTSTRAP_INSUFFICIENT in result.reason_codes
    assert ProtocolReasonCode.EVIDENCE_MEASUREMENT_INSUFFICIENT in result.reason_codes
