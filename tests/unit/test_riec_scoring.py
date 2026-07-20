from __future__ import annotations

import math
from typing import cast

import pytest

from riec_guard.riec.fit import FitFailure, OlsFitResult, fit_ols
from riec_guard.riec.grouped_cv import CandidateEvaluation, EvaluationStatus
from riec_guard.riec.registry import FROZEN_CANDIDATE_IDS
from riec_guard.riec.scoring import (
    ScoringFailure,
    SwitchStatus,
    TiePolicy,
    score_candidate,
    switching_boundary,
)
from riec_guard.riec.selection import compute_riec_decision


def test_ols_uses_realized_rank_and_exact_information_criteria() -> None:
    fit = fit_ols(
        ((1.0,), (1.0,), (1.0,), (1.0,)),
        (1.0, 2.0, 3.0, 4.0),
        n_eff=4,
    )

    expected_rss = 5.0
    expected_aic = 4.0 * math.log(expected_rss / 4.0) + 2.0
    expected_aicc = expected_aic + (2.0 * 1.0 * 2.0) / (4.0 - 1.0 - 1.0)
    expected_bic_eff = 4.0 * math.log(expected_rss / 4.0) + math.log(4.0)

    assert fit.coefficients == pytest.approx((2.5,))
    assert fit.n_rows == 4
    assert fit.n_columns == 1
    assert fit.realized_rank == 1
    assert fit.residual_degrees_freedom == 3
    assert fit.rss == pytest.approx(expected_rss)
    assert fit.aic == pytest.approx(expected_aic)
    assert fit.aicc == pytest.approx(expected_aicc)
    assert fit.bic_eff == pytest.approx(expected_bic_eff)
    assert fit.singular_tolerance == pytest.approx(float.fromhex("0x1.0000000000000p-52") * 4.0)


def test_aicc_is_unavailable_when_denominator_condition_is_not_met() -> None:
    fit = fit_ols(((1.0,), (1.0,)), (1.0, 2.0), n_eff=2)

    assert fit.realized_rank == 1
    assert fit.aicc is None


def test_ols_rank_deficiency_fails_closed() -> None:
    with pytest.raises(FitFailure) as captured:
        fit_ols(
            ((1.0, 1.0), (1.0, 1.0), (1.0, 1.0)),
            (1.0, 2.0, 3.0),
            n_eff=3,
        )

    assert captured.value.code == "CANDIDATE_DESIGN_RANK_DEFICIENT"


def test_ols_zero_rss_fails_closed_without_clipping() -> None:
    with pytest.raises(FitFailure) as captured:
        fit_ols(((1.0,), (1.0,), (1.0,)), (0.0, 0.0, 0.0), n_eff=3)

    assert captured.value.code == "CANDIDATE_ZERO_RSS"


def test_score_uses_exact_xpe_lambda_and_c_lambda_equations() -> None:
    score = score_candidate(
        bic_eff=10.0,
        risk=2.0,
        baseline_risk=8.0,
        n_eff=100,
        c=2.0,
    )

    expected_xpe = 4.0
    expected_log_xpe = math.log(4.0)
    expected_lambda = 2.0 / math.log(100.0)
    expected_c_score = 10.0 - expected_lambda * expected_log_xpe
    assert score.xpe == expected_xpe
    assert score.log_xpe == expected_log_xpe
    assert score.lambda_n == expected_lambda
    assert score.c_score == expected_c_score


def test_worse_than_baseline_risk_remains_a_finite_unfavorable_score() -> None:
    score = score_candidate(
        bic_eff=10.0,
        risk=8.0,
        baseline_risk=2.0,
        n_eff=100,
        c=1.0,
    )

    assert score.xpe == 0.25
    assert score.log_xpe < 0.0
    assert score.c_score > score.bic_eff


def test_zero_baseline_fails_and_positive_near_zero_baseline_is_not_clipped() -> None:
    with pytest.raises(ScoringFailure) as captured:
        score_candidate(
            bic_eff=10.0,
            risk=1.0,
            baseline_risk=0.0,
            n_eff=100,
            c=1.0,
        )
    assert captured.value.code == "RIEC_INVALID_BASELINE_RISK"

    near_zero = score_candidate(
        bic_eff=10.0,
        risk=1.0,
        baseline_risk=1e-300,
        n_eff=100,
        c=1.0,
    )
    assert near_zero.xpe == 1e-300
    assert math.isfinite(near_zero.c_score)


def test_c_zero_removes_and_larger_c_scales_predictive_contribution() -> None:
    at_zero = score_candidate(
        bic_eff=10.0,
        risk=1.0,
        baseline_risk=2.0,
        n_eff=100,
        c=0.0,
    )
    at_one = score_candidate(
        bic_eff=10.0,
        risk=1.0,
        baseline_risk=2.0,
        n_eff=100,
        c=1.0,
    )
    at_ten = score_candidate(
        bic_eff=10.0,
        risk=1.0,
        baseline_risk=2.0,
        n_eff=100,
        c=10.0,
    )

    assert at_zero.lambda_n == 0.0
    assert at_zero.c_score == 10.0
    assert at_ten.c_score < at_one.c_score < at_zero.c_score
    assert 10.0 - at_ten.c_score == pytest.approx(10.0 * (10.0 - at_one.c_score))


def test_frozen_tie_policy_uses_max_threshold_and_order_independent_set() -> None:
    policy = TiePolicy(abs_tolerance=1e-6, rel_tolerance=1e-8)
    assert policy.threshold(10.0) == 1e-6
    assert policy.threshold(1_000_000.0) == 0.01

    scores = (
        ("M0_intercept", 10.0),
        ("M1_product", 10.0 + 5e-7),
        ("M2_product_stream", 10.0 + 2e-6),
    )

    def equivalence_set(
        ordered_scores: tuple[tuple[str, float], ...],
    ) -> frozenset[str]:
        winner_score = min(score for _, score in ordered_scores)
        return frozenset(
            candidate_id
            for candidate_id, score in ordered_scores
            if policy.is_equivalent(score=score, winner_score=winner_score)
        )

    expected = frozenset({"M0_intercept", "M1_product"})
    assert equivalence_set(scores) == expected
    assert equivalence_set(tuple(reversed(scores))) == expected


@pytest.mark.parametrize(
    ("kwargs", "expected_status"),
    (
        (
            {
                "candidate_a": "M0_intercept",
                "candidate_b": "M1_product",
                "bic_eff_a": 0.0,
                "bic_eff_b": 1.0,
                "risk_a": 2.0,
                "risk_b": 1.0,
                "n_eff": 100,
            },
            SwitchStatus.FINITE,
        ),
        (
            {
                "candidate_a": "M0_intercept",
                "candidate_b": "M1_product",
                "bic_eff_a": 0.0,
                "bic_eff_b": 1.0,
                "risk_a": 1.0,
                "risk_b": 1.0,
                "n_eff": 100,
            },
            SwitchStatus.PARALLEL_NO_SWITCH,
        ),
        (
            {
                "candidate_a": "M0_intercept",
                "candidate_b": "M1_product",
                "bic_eff_a": 1.0,
                "bic_eff_b": 1.0,
                "risk_a": 1.0,
                "risk_b": 1.0,
                "n_eff": 100,
            },
            SwitchStatus.COINCIDENT,
        ),
        (
            {
                "candidate_a": "M0_intercept",
                "candidate_b": "M1_product",
                "bic_eff_a": 1.0,
                "bic_eff_b": 0.0,
                "risk_a": 2.0,
                "risk_b": 1.0,
                "n_eff": 100,
            },
            SwitchStatus.OUTSIDE_NONNEGATIVE_DOMAIN,
        ),
        (
            {
                "candidate_a": "M0_intercept",
                "candidate_b": None,
                "bic_eff_a": 0.0,
                "bic_eff_b": None,
                "risk_a": 2.0,
                "risk_b": None,
                "n_eff": 100,
            },
            SwitchStatus.NOT_AVAILABLE,
        ),
    ),
)
def test_all_switching_boundary_statuses_are_explicit(
    kwargs: dict[str, str | float | int | None],
    expected_status: SwitchStatus,
) -> None:
    boundary = switching_boundary(
        candidate_a=cast(str, kwargs["candidate_a"]),
        candidate_b=cast(str | None, kwargs["candidate_b"]),
        bic_eff_a=cast(float | None, kwargs["bic_eff_a"]),
        bic_eff_b=cast(float | None, kwargs["bic_eff_b"]),
        risk_a=cast(float | None, kwargs["risk_a"]),
        risk_b=cast(float | None, kwargs["risk_b"]),
        n_eff=cast(int, kwargs["n_eff"]),
    )

    assert boundary.status is expected_status


def test_finite_switch_boundary_substitutes_and_flips_on_both_sides() -> None:
    expected_boundary = math.log(100.0) / math.log(2.0)
    boundary = switching_boundary(
        candidate_a="M0_intercept",
        candidate_b="M1_product",
        bic_eff_a=0.0,
        bic_eff_b=1.0,
        risk_a=2.0,
        risk_b=1.0,
        n_eff=100,
        current_c=expected_boundary,
    )

    assert boundary.status is SwitchStatus.FINITE
    assert boundary.switch_c == pytest.approx(expected_boundary)
    assert boundary.preference_below == "M0_intercept"
    assert boundary.preference_above == "M1_product"
    assert boundary.current_c == expected_boundary
    assert boundary.preference_at_current is None

    assert boundary.switch_c is not None
    at_boundary_a = score_candidate(
        bic_eff=0.0,
        risk=2.0,
        baseline_risk=2.0,
        n_eff=100,
        c=boundary.switch_c,
    )
    at_boundary_b = score_candidate(
        bic_eff=1.0,
        risk=1.0,
        baseline_risk=2.0,
        n_eff=100,
        c=boundary.switch_c,
    )
    assert at_boundary_a.c_score == pytest.approx(at_boundary_b.c_score)

    below = boundary.switch_c / 2.0
    above = boundary.switch_c * 1.5
    below_a = score_candidate(
        bic_eff=0.0,
        risk=2.0,
        baseline_risk=2.0,
        n_eff=100,
        c=below,
    )
    below_b = score_candidate(
        bic_eff=1.0,
        risk=1.0,
        baseline_risk=2.0,
        n_eff=100,
        c=below,
    )
    above_a = score_candidate(
        bic_eff=0.0,
        risk=2.0,
        baseline_risk=2.0,
        n_eff=100,
        c=above,
    )
    above_b = score_candidate(
        bic_eff=1.0,
        risk=1.0,
        baseline_risk=2.0,
        n_eff=100,
        c=above,
    )
    assert below_a.c_score < below_b.c_score
    assert above_b.c_score < above_a.c_score


def test_switch_boundary_uses_stable_log_ratio_for_extreme_finite_risks() -> None:
    boundary = switching_boundary(
        candidate_a="M0_intercept",
        candidate_b="M1_product",
        bic_eff_a=0.0,
        bic_eff_b=1.0,
        risk_a=1e-300,
        risk_b=1e300,
        n_eff=100,
        current_c=1.0,
    )

    assert boundary.status is SwitchStatus.OUTSIDE_NONNEGATIVE_DOMAIN
    assert boundary.switch_c is not None
    assert math.isfinite(boundary.switch_c)
    assert boundary.preference_at_current == boundary.preference_above


def test_selection_exposes_near_tie_equivalence_independent_of_input_order() -> None:
    def successful(candidate_id: str, bic_eff: float) -> CandidateEvaluation:
        fit = OlsFitResult(
            coefficients=(1.0,),
            n_rows=80,
            n_columns=1,
            realized_rank=1,
            residual_degrees_freedom=79,
            rss=1.0,
            aic=1.0,
            aicc=1.1,
            bic_eff=bic_eff,
            singular_tolerance=1e-12,
        )
        return CandidateEvaluation(
            candidate_id=candidate_id,
            status=EvaluationStatus.OK,
            full_fit=fit,
            grouped_risk=1.0,
            group_balanced_risk=1.0,
            n_rows=80,
            n_groups=4,
            folds=(),
            failure_code=None,
        )

    evaluations = [successful("M0_intercept", 10.0), successful("M1_product", 10.0000005)]
    evaluations.extend(
        CandidateEvaluation(
            candidate_id=candidate_id,
            status=EvaluationStatus.INELIGIBLE,
            full_fit=None,
            grouped_risk=None,
            group_balanced_risk=None,
            n_rows=80,
            n_groups=4,
            folds=(),
            failure_code="CANDIDATE_REQUIRED_SEMANTIC_MISSING",
        )
        for candidate_id in FROZEN_CANDIDATE_IDS[2:]
    )

    first = compute_riec_decision(
        tuple(evaluations),
        c=0.0,
        near_tie_abs_tol=1e-6,
        near_tie_rel_tol=1e-8,
    )
    reversed_input = compute_riec_decision(
        tuple(reversed(evaluations)),
        c=0.0,
        near_tie_abs_tol=1e-6,
        near_tie_rel_tol=1e-8,
    )

    assert first.raw_numeric_winner == "M0_intercept"
    assert first.winner is None
    assert first.runner_up == "M1_product"
    assert first.near_tie is True
    assert first.equivalence_set == ("M0_intercept", "M1_product")
    assert reversed_input.equivalence_set == first.equivalence_set
