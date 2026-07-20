from __future__ import annotations

from types import SimpleNamespace

import numpy as np
import pytest
from scipy import stats  # type: ignore[import-untyped]

from riec_guard.contract.models import ProtocolId, ProtocolStatus
from riec_guard.protocols.gaussian_tail import run_gaussian_residual_tail
from riec_guard.protocols.models import CrossFittedPrediction, ProtocolReasonCode
from riec_guard.protocols.student_t_tail import run_student_t_residual_tail


def _heavy_tail_fixture() -> tuple[tuple[float, ...], tuple[str, ...], CrossFittedPrediction]:
    n_rows = 48
    residuals = tuple(
        0.45 * float(stats.t.ppf((index + 0.5) / n_rows, df=4.0)) for index in range(n_rows)
    )
    predictions = (12.0,) * n_rows
    quantities = tuple(
        prediction + residual for prediction, residual in zip(predictions, residuals)
    )
    groups = tuple(f"G{index % 8}" for index in range(n_rows))
    return quantities, groups, CrossFittedPrediction("M0_intercept", predictions)


def test_h3_bounded_fit_is_reproducible_and_differs_from_gaussian_tail() -> None:
    quantities, groups, prediction = _heavy_tail_fixture()
    first = run_student_t_residual_tail(
        quantities,
        groups,
        (prediction,),
        lower_limit=10.0,
        alpha=0.05,
        maximum_screening_shift=4.0,
        unit="mL",
    )
    second = run_student_t_residual_tail(
        quantities,
        groups,
        (prediction,),
        lower_limit=10.0,
        alpha=0.05,
        maximum_screening_shift=4.0,
        unit="mL",
    )
    gaussian = run_gaussian_residual_tail(
        quantities,
        groups,
        (prediction,),
        lower_limit=10.0,
        alpha=0.05,
        maximum_screening_shift=4.0,
        unit="mL",
    )

    assert first == second
    assert first.protocol_id is ProtocolId.H3_STUDENT_T_RESIDUAL_TAIL
    assert first.status in {ProtocolStatus.OK, ProtocolStatus.WARNING}
    assert first.point_estimate is not None
    assert gaussian.point_estimate is not None
    # Parametric scale definitions differ, so tail direction is not fixed at every
    # alpha; the frozen requirement is a meaningful, explicit protocol difference.
    assert abs(first.point_estimate - gaussian.point_estimate) > 0.02
    fitted_df = first.metric("fitted_df_min")
    assert isinstance(fitted_df, float)
    assert 2.1 < fitted_df < 100.0
    canonical = first.to_canonical_entry(evidence_ids=("EV-PROTOCOL-123456789ABC",))
    assert canonical.point_estimate == first.point_estimate
    assert canonical.uncertainty is not None
    assert canonical.uncertainty.conditional_on_selection is True


def test_h3_tiny_time_budget_returns_typed_timeout_without_gaussian_fallback() -> None:
    quantities, groups, prediction = _heavy_tail_fixture()
    result = run_student_t_residual_tail(
        quantities,
        groups,
        (prediction,),
        lower_limit=10.0,
        alpha=0.05,
        maximum_screening_shift=4.0,
        unit="mL",
        fit_timeout_seconds=1.0e-12,
    )

    assert result.status is ProtocolStatus.INELIGIBLE
    assert result.point_estimate is None
    assert ProtocolReasonCode.STUDENT_T_FIT_TIMEOUT in {warning.code for warning in result.warnings}
    assert "no gaussian" in result.algorithm_notes.lower()


def test_h3_degenerate_scale_is_ineligible_without_substitution() -> None:
    result = run_student_t_residual_tail(
        (12.0,) * 8,
        ("A",) * 4 + ("B",) * 4,
        (CrossFittedPrediction("M0_intercept", (12.0,) * 8),),
        lower_limit=10.0,
        alpha=0.05,
        maximum_screening_shift=4.0,
        unit="mL",
    )

    assert result.status is ProtocolStatus.INELIGIBLE
    assert ProtocolReasonCode.PARAMETRIC_DEGENERATE_SCALE in {
        warning.code for warning in result.warnings
    }


def test_h3_rejects_fit_budget_above_frozen_three_second_maximum() -> None:
    quantities, groups, prediction = _heavy_tail_fixture()
    result = run_student_t_residual_tail(
        quantities,
        groups,
        (prediction,),
        lower_limit=10.0,
        alpha=0.05,
        maximum_screening_shift=4.0,
        unit="mL",
        fit_timeout_seconds=3.000001,
    )

    assert result.status is ProtocolStatus.INELIGIBLE
    assert result.point_estimate is None


@pytest.mark.parametrize(
    ("optimizer_result", "expected_code"),
    (
        (
            SimpleNamespace(
                success=True,
                x=np.asarray((2.1, 0.0, 0.0)),
                fun=1.0,
                nit=1,
            ),
            ProtocolReasonCode.STUDENT_T_DF_BOUNDARY,
        ),
        (
            SimpleNamespace(
                success=False,
                x=np.asarray((10.0, 0.0, 0.0)),
                fun=1.0,
                nit=1,
            ),
            ProtocolReasonCode.STUDENT_T_FIT_NONCONVERGENCE,
        ),
    ),
)
def test_h3_optimizer_boundary_and_nonconvergence_are_explicit(
    monkeypatch: pytest.MonkeyPatch,
    optimizer_result: SimpleNamespace,
    expected_code: ProtocolReasonCode,
) -> None:
    quantities, groups, prediction = _heavy_tail_fixture()
    monkeypatch.setattr(
        "riec_guard.protocols.student_t_tail.optimize.minimize",
        lambda *args, **kwargs: optimizer_result,
    )

    result = run_student_t_residual_tail(
        quantities,
        groups,
        (prediction,),
        lower_limit=10.0,
        alpha=0.05,
        maximum_screening_shift=4.0,
        unit="mL",
    )

    assert result.status is ProtocolStatus.INELIGIBLE
    assert expected_code in {warning.code for warning in result.warnings}
