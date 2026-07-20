from __future__ import annotations

from riec_guard.contract.models import ProtocolStatus
from riec_guard.protocols.models import G1Status, ProtocolReasonCode, StabilitySummary
from riec_guard.protocols.stability import run_ordered_stability_screen


def _run(
    quantities: tuple[float, ...],
    times: tuple[float, ...],
    *,
    order_confirmed: bool = True,
) -> StabilitySummary:
    n_rows = len(quantities)
    return run_ordered_stability_screen(
        quantities,
        ("P",) * n_rows,
        ("S",) * n_rows,
        times,
        ((),) * n_rows,
        order_confirmed=order_confirmed,
        stream_confirmed=True,
        min_points_per_stream=20,
        minimum_coverage=0.6,
    )


def test_validated_sort_is_invariant_to_input_order() -> None:
    quantities = tuple(float(-1 if index % 2 == 0 else 1) for index in range(20))
    times = tuple(float(index) for index in range(20))
    canonical = _run(quantities, times)
    permutation = tuple(reversed(range(20)))
    shuffled = _run(
        tuple(quantities[index] for index in permutation),
        tuple(times[index] for index in permutation),
    )

    assert canonical == shuffled
    assert canonical.state is G1Status.PASS
    assert canonical.computation.status is ProtocolStatus.OK
    assert canonical.ordered_coverage == 1.0


def test_unconfirmed_order_is_ineligible_and_does_not_use_row_order() -> None:
    result = _run((0.0,) * 20, tuple(float(index) for index in range(20)), order_confirmed=False)

    assert result.state is G1Status.INELIGIBLE
    assert result.computation.status is ProtocolStatus.INELIGIBLE
    assert result.computation.warnings[0].code is ProtocolReasonCode.ORDER_UNCONFIRMED


def test_injected_change_point_materially_downgrades_screen() -> None:
    result = _run((0.0,) * 10 + (10.0,) * 10, tuple(float(index) for index in range(20)))

    assert result.state is G1Status.MATERIAL_WARNING
    codes = {warning.code for warning in result.computation.warnings}
    assert ProtocolReasonCode.STABILITY_EIGHT_ONE_SIDE in codes
    assert ProtocolReasonCode.STABILITY_QUARTILE_SHIFT in codes
    assert any(warning.severity.value == "material" for warning in result.computation.warnings)


def test_moving_ranges_never_cross_streams() -> None:
    result = run_ordered_stability_screen(
        (0.0,) * 20 + (100.0,) * 20,
        ("P",) * 40,
        ("S1",) * 20 + ("S2",) * 20,
        tuple(float(index) for index in range(20)) * 2,
        ((),) * 40,
        order_confirmed=True,
        stream_confirmed=True,
        min_points_per_stream=20,
        minimum_coverage=0.6,
    )

    assert result.state is G1Status.PASS
    assert not any(
        warning.code is ProtocolReasonCode.STABILITY_POINT_BEYOND_3SIGMA
        for warning in result.computation.warnings
    )


def test_unresolved_tied_segment_is_not_silently_ordered() -> None:
    result = run_ordered_stability_screen(
        tuple(float(index % 2) for index in range(22)),
        ("P",) * 22,
        ("S",) * 22,
        (0.0, 0.0) + tuple(float(index) for index in range(1, 21)),
        ((),) * 22,
        order_confirmed=True,
        stream_confirmed=True,
        min_points_per_stream=20,
        minimum_coverage=0.6,
    )

    assert result.ordered_coverage == 20 / 22
    assert any(
        warning.code is ProtocolReasonCode.ORDER_TIE_UNRESOLVED
        for warning in result.computation.warnings
    )


def test_resolved_tie_break_is_used_without_losing_coverage() -> None:
    quantities = tuple(float(index % 2) for index in range(20))
    result = run_ordered_stability_screen(
        quantities,
        ("P",) * 20,
        ("S",) * 20,
        (0.0, 0.0) + tuple(float(index) for index in range(1, 19)),
        (("2",), ("1",)) + tuple((str(index),) for index in range(2, 20)),
        order_confirmed=True,
        stream_confirmed=True,
        min_points_per_stream=20,
        minimum_coverage=0.6,
    )

    assert result.ordered_coverage == 1.0
    assert not any(
        warning.code is ProtocolReasonCode.ORDER_TIE_UNRESOLVED
        for warning in result.computation.warnings
    )


def test_point_beyond_three_mr_sigma_rule_is_visible() -> None:
    result = _run((0.0,) * 19 + (10.0,), tuple(float(index) for index in range(20)))

    assert result.state is G1Status.MATERIAL_WARNING
    assert result.computation.metric("point_beyond_3sigma_count") == 1
    assert ProtocolReasonCode.STABILITY_POINT_BEYOND_3SIGMA in {
        warning.code for warning in result.computation.warnings
    }


def test_six_monotone_rule_is_visible() -> None:
    result = _run(
        tuple(float(index) for index in range(20)), tuple(float(index) for index in range(20))
    )

    assert result.state is G1Status.MATERIAL_WARNING
    assert result.computation.metric("six_monotone_run_count") == 1
    assert ProtocolReasonCode.STABILITY_SIX_MONOTONE in {
        warning.code for warning in result.computation.warnings
    }


def test_degenerate_moving_range_uses_declared_sample_sd_fallback() -> None:
    result = _run((1.0,) * 20, tuple(float(index) for index in range(20)))

    assert result.state is G1Status.PASS
    assert result.computation.status is ProtocolStatus.WARNING
    assert ProtocolReasonCode.MR_SCALE_FALLBACK in {
        warning.code for warning in result.computation.warnings
    }
