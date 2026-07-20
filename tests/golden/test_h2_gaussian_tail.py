from __future__ import annotations

import math

import pytest

from riec_guard.contract.models import ProtocolId, ProtocolStatus, WarningSeverity
from riec_guard.protocols.gaussian_tail import run_gaussian_residual_tail
from riec_guard.protocols.models import CrossFittedPrediction, ProtocolReasonCode


def _stable_fixture() -> tuple[tuple[float, ...], tuple[str, ...], CrossFittedPrediction]:
    residual_block = (-0.9, -0.3, 0.3, 0.9)
    residuals = residual_block * 3
    predictions = (12.0,) * len(residuals)
    quantities = tuple(
        prediction + residual for prediction, residual in zip(predictions, residuals)
    )
    groups = ("A",) * 4 + ("B",) * 4 + ("C",) * 4
    return quantities, groups, CrossFittedPrediction("M0_intercept", predictions)


def test_h2_deterministic_solution_matches_direct_gaussian_tail_risk() -> None:
    quantities, groups, prediction = _stable_fixture()
    result = run_gaussian_residual_tail(
        quantities,
        groups,
        (prediction,),
        lower_limit=10.0,
        alpha=0.10,
        maximum_screening_shift=4.0,
        unit="mL",
    )

    assert result.protocol_id is ProtocolId.H2_GAUSSIAN_RESIDUAL_TAIL
    assert result.status is ProtocolStatus.OK
    assert result.point_estimate is not None
    residuals = tuple(value - 12.0 for value in quantities)
    residual_mean = math.fsum(residuals) / len(residuals)
    residual_sd = math.sqrt(
        math.fsum((value - residual_mean) ** 2 for value in residuals) / (len(residuals) - 1)
    )

    def risk(shift: float) -> float:
        z = (10.0 + shift - 12.0 - residual_mean) / residual_sd
        return 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))

    assert risk(result.point_estimate) <= 0.10 + 1.0e-10
    assert risk(result.point_estimate + 2.0e-9) > 0.10
    assert result.metric("residual_estimator") == "sample-mean-sample-sd.v1"
    assert result.metric("bisection_tolerance") == pytest.approx(1.0e-9)
    canonical = result.to_canonical_entry(evidence_ids=("EV-PROTOCOL-123456789ABC",))
    assert canonical.point_estimate == result.point_estimate
    assert canonical.uncertainty is not None
    assert canonical.uncertainty.conditional_on_selection is True


def test_h2_skew_and_heavy_tail_diagnostics_are_material_not_conservative_claims() -> None:
    residuals = (-8.0, 0.0, 0.0, 0.0) * 3
    predictions = (12.0,) * len(residuals)
    quantities = tuple(
        prediction + residual for prediction, residual in zip(predictions, residuals)
    )
    result = run_gaussian_residual_tail(
        quantities,
        ("A",) * 4 + ("B",) * 4 + ("C",) * 4,
        (CrossFittedPrediction("M0_intercept", predictions),),
        lower_limit=10.0,
        alpha=0.10,
        maximum_screening_shift=4.0,
        unit="mL",
    )

    assert result.status is ProtocolStatus.WARNING
    codes = {warning.code for warning in result.warnings}
    assert ProtocolReasonCode.RESIDUAL_SKEW_DIAGNOSTIC in codes
    assert all(
        warning.severity is WarningSeverity.MATERIAL
        for warning in result.warnings
        if warning.code is ProtocolReasonCode.RESIDUAL_SKEW_DIAGNOSTIC
    )
    assert "automatically conservative" not in result.algorithm_notes.lower()


def test_h2_degenerate_residual_scale_is_ineligible_without_fallback() -> None:
    result = run_gaussian_residual_tail(
        (12.0,) * 8,
        ("A",) * 4 + ("B",) * 4,
        (CrossFittedPrediction("M0_intercept", (12.0,) * 8),),
        lower_limit=10.0,
        alpha=0.10,
        maximum_screening_shift=4.0,
        unit="mL",
    )

    assert result.status is ProtocolStatus.INELIGIBLE
    assert result.point_estimate is None
    assert ProtocolReasonCode.PARAMETRIC_DEGENERATE_SCALE in {
        warning.code for warning in result.warnings
    }


@pytest.mark.parametrize(
    ("quantities", "groups"),
    (
        ((11.0,) * 4 + (13.0,) * 4, ("A",) * 4 + ("B",) * 4),
        ((10.5, 11.5, 12.5, 13.5), ("A", "B", "C", "D")),
    ),
)
def test_h2_unavailable_groupwise_scale_is_material_not_silently_ok(
    quantities: tuple[float, ...],
    groups: tuple[str, ...],
) -> None:
    result = run_gaussian_residual_tail(
        quantities,
        groups,
        (CrossFittedPrediction("M0_intercept", (12.0,) * len(quantities)),),
        lower_limit=9.0,
        alpha=0.10,
        maximum_screening_shift=4.0,
        unit="mL",
    )

    assert result.status is ProtocolStatus.WARNING
    assert result.metric("groupwise_scale_ratio_unbounded") is True
    warning = next(
        item
        for item in result.warnings
        if item.code is ProtocolReasonCode.GROUPWISE_SCALE_DIAGNOSTIC
    )
    assert warning.severity is WarningSeverity.MATERIAL
