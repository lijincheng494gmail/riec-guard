from __future__ import annotations

import pytest

from riec_guard.contract.models import ProtocolId, ProtocolStatus
from riec_guard.protocols.empirical import run_empirical_headroom, run_mean_diagnostic
from riec_guard.protocols.models import ProtocolReasonCode


def test_h1_exact_strict_boundary_matches_phase_d_golden_case() -> None:
    result = run_empirical_headroom(
        (9.0, 10.0, 11.0, 12.0, 13.0),
        ("A", "A", "B", "B", "C"),
        lower_limit=10.0,
        alpha=0.20,
        unit="mL",
        min_rows=5,
        min_groups=3,
        min_expected_tail_count=1.0,
    )

    assert result.protocol_id is ProtocolId.H1_GROUP_EMPIRICAL_QUANTILE
    assert result.status is ProtocolStatus.OK
    assert result.point_estimate == 0.0
    assert result.metric("k_floor_alpha_n") == 1
    assert result.metric("order_statistic_index_one_based") == 2
    assert result.metric("raw_boundary") == 0.0
    assert result.metric("strict_underfills_at_raw_boundary") == 1
    assert result.warnings == ()


def test_h1_tied_equality_is_not_underfill_but_warns_about_discreteness() -> None:
    result = run_empirical_headroom(
        (10.0, 10.0, 10.0, 12.0),
        ("A", "A", "B", "B"),
        lower_limit=10.0,
        alpha=0.25,
        unit="mL",
        min_rows=4,
        min_groups=2,
        min_expected_tail_count=1.0,
    )

    assert result.status is ProtocolStatus.WARNING
    assert result.point_estimate == 0.0
    assert result.metric("boundary_tie_multiplicity") == 3
    assert result.metric("strict_underfills_at_final_headroom") == 0
    assert tuple(warning.code for warning in result.warnings) == (
        ProtocolReasonCode.EMPIRICAL_BOUNDARY_TIE,
    )


def test_h1_ineligible_support_and_baseline_breach_fail_closed() -> None:
    result = run_empirical_headroom(
        (8.0, 9.0, 10.0, 11.0),
        ("A", "A", "B", "B"),
        lower_limit=10.0,
        alpha=0.25,
        unit="mL",
        min_rows=80,
        min_groups=8,
        min_expected_tail_count=5.0,
    )

    assert result.status is ProtocolStatus.INELIGIBLE
    assert result.point_estimate == 0.0
    assert {
        ProtocolReasonCode.EMPIRICAL_INSUFFICIENT_ROWS,
        ProtocolReasonCode.EMPIRICAL_INSUFFICIENT_GROUPS,
        ProtocolReasonCode.EMPIRICAL_INSUFFICIENT_TAIL_SUPPORT,
        ProtocolReasonCode.EMPIRICAL_BASELINE_EXCEEDS_TAIL_LIMIT,
    }.issubset({warning.code for warning in result.warnings})
    assert result.eligible_headroom is False


def test_h1_decimal_policy_boundary_does_not_lose_an_order_statistic() -> None:
    result = run_empirical_headroom(
        tuple(float(value) for value in range(10, 110)),
        tuple(f"G{index % 4}" for index in range(100)),
        lower_limit=0.0,
        alpha=0.29,
        unit="mL",
        min_rows=100,
        min_groups=4,
        min_expected_tail_count=29.0,
    )

    assert result.status is ProtocolStatus.OK
    assert result.metric("expected_tail_count") == 29.0
    assert result.metric("k_floor_alpha_n") == 29
    assert result.metric("order_statistic_index_one_based") == 30
    assert result.point_estimate == 39.0


def test_d0_is_descriptive_mean_overfill_and_canonical_projection_validates() -> None:
    result = run_mean_diagnostic(
        (10.5, 11.5, 12.5),
        nominal_quantity=11.0,
        lower_limit=10.0,
        unit="mL",
    )

    assert result.protocol_id is ProtocolId.D0_MEAN_DIAGNOSTIC
    assert result.point_estimate == pytest.approx(0.5)
    assert result.metric("mean_margin_above_lower_limit") == pytest.approx(1.5)
    entry = result.to_canonical_entry(evidence_ids=("EV-PROTOCOL-123456789ABC",))
    assert entry.protocol_id is ProtocolId.D0_MEAN_DIAGNOSTIC
    assert entry.point_estimate == pytest.approx(0.5)
