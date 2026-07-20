"""Exact RIEC-L1 score, tie, and pairwise switching calculations."""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum


@dataclass(frozen=True, slots=True)
class ScoringFailure(ValueError):
    """Fail-closed score error carrying a stable, non-sensitive reason code."""

    code: str


@dataclass(frozen=True, slots=True)
class RiecScore:
    """Immutable decomposition of one candidate's exact RIEC-L1 score."""

    bic_eff: float
    risk: float
    baseline_risk: float
    xpe: float
    log_xpe: float
    lambda_n: float
    c_score: float


@dataclass(frozen=True, slots=True)
class TiePolicy:
    """Predeclared score-equivalence policy."""

    abs_tolerance: float
    rel_tolerance: float

    def __post_init__(self) -> None:
        if not math.isfinite(self.abs_tolerance) or self.abs_tolerance < 0.0:
            raise ScoringFailure("RIEC_INVALID_TIE_POLICY")
        if not math.isfinite(self.rel_tolerance) or self.rel_tolerance < 0.0:
            raise ScoringFailure("RIEC_INVALID_TIE_POLICY")

    def threshold(self, winner_score: float) -> float:
        """Return ``max(abs_tol, rel_tol * max(1, abs(winner_score)))``."""

        if not math.isfinite(winner_score):
            raise ScoringFailure("RIEC_SCORE_UNAVAILABLE")
        return max(
            self.abs_tolerance,
            self.rel_tolerance * max(1.0, abs(winner_score)),
        )

    def is_equivalent(self, *, score: float, winner_score: float) -> bool:
        """Return whether a finite score is within the declared winner tolerance."""

        if not math.isfinite(score):
            raise ScoringFailure("RIEC_SCORE_UNAVAILABLE")
        return abs(score - winner_score) <= self.threshold(winner_score)


class SwitchStatus(StrEnum):
    """Stable status for the pairwise schedule boundary."""

    FINITE = "finite"
    PARALLEL_NO_SWITCH = "parallel_no_switch"
    COINCIDENT = "coincident"
    OUTSIDE_NONNEGATIVE_DOMAIN = "outside_nonnegative_domain"
    NOT_AVAILABLE = "not_available"


@dataclass(frozen=True, slots=True)
class SwitchingBoundary:
    """Typed pairwise RIEC-L1 switching diagnostic."""

    candidate_a: str
    candidate_b: str | None
    status: SwitchStatus
    switch_c: float | None
    current_c: float
    identifiable: bool
    preference_below: str | None
    preference_above: str | None
    preference_at_current: str | None
    interpretation: str


def score_candidate(
    *,
    bic_eff: float,
    risk: float,
    baseline_risk: float,
    n_eff: int,
    c: float,
) -> RiecScore:
    """Calculate the exact baseline-normalized RIEC-L1 candidate score.

    ``XPE = baseline_risk / risk``
    ``lambda_n = c / log(n_eff)``
    ``C_lambda = BIC_eff - lambda_n * log(XPE)``
    """

    if not math.isfinite(bic_eff):
        raise ScoringFailure("RIEC_SCORE_UNAVAILABLE")
    if not math.isfinite(risk) or risk <= 0.0:
        raise ScoringFailure("RIEC_INVALID_RISK")
    if not math.isfinite(baseline_risk) or baseline_risk <= 0.0:
        raise ScoringFailure("RIEC_INVALID_BASELINE_RISK")
    if isinstance(n_eff, bool) or not isinstance(n_eff, int) or n_eff <= 1:
        raise ScoringFailure("RIEC_INVALID_N_EFF")
    if not math.isfinite(c) or c < 0.0:
        raise ScoringFailure("RIEC_INVALID_C")

    try:
        xpe = baseline_risk / risk
    except ArithmeticError as error:
        raise ScoringFailure("RIEC_SCORE_UNAVAILABLE") from error
    if not math.isfinite(xpe) or xpe <= 0.0:
        raise ScoringFailure("RIEC_SCORE_UNAVAILABLE")
    try:
        log_xpe = math.log(xpe)
        lambda_n = c / math.log(n_eff)
        c_score = bic_eff - lambda_n * log_xpe
    except ArithmeticError as error:
        raise ScoringFailure("RIEC_SCORE_UNAVAILABLE") from error
    if not all(math.isfinite(value) for value in (log_xpe, lambda_n, c_score)):
        raise ScoringFailure("RIEC_SCORE_UNAVAILABLE")

    return RiecScore(
        bic_eff=bic_eff,
        risk=risk,
        baseline_risk=baseline_risk,
        xpe=xpe,
        log_xpe=log_xpe,
        lambda_n=lambda_n,
        c_score=c_score,
    )


def switching_boundary(
    *,
    candidate_a: str,
    candidate_b: str | None,
    bic_eff_a: float | None,
    bic_eff_b: float | None,
    risk_a: float | None,
    risk_b: float | None,
    n_eff: int,
    current_c: float = 0.0,
) -> SwitchingBoundary:
    """Solve the exact pairwise RIEC-L1 boundary without refitting.

    With ``delta_bic = BIC_eff(B) - BIC_eff(A)`` and
    ``log_risk_ratio = log(risk(A) / risk(B))``, the score lines are equal at
    ``c* = delta_bic * log(n_eff) / log_risk_ratio``.
    """

    if isinstance(n_eff, bool) or not isinstance(n_eff, int) or n_eff <= 1:
        raise ScoringFailure("RIEC_INVALID_N_EFF")
    if not math.isfinite(current_c) or current_c < 0.0:
        raise ScoringFailure("RIEC_INVALID_C")
    if candidate_b is None or not _complete_pairwise_inputs(
        bic_eff_a=bic_eff_a,
        bic_eff_b=bic_eff_b,
        risk_a=risk_a,
        risk_b=risk_b,
    ):
        return SwitchingBoundary(
            candidate_a=candidate_a,
            candidate_b=candidate_b,
            status=SwitchStatus.NOT_AVAILABLE,
            switch_c=None,
            current_c=current_c,
            identifiable=False,
            preference_below=None,
            preference_above=None,
            preference_at_current=None,
            interpretation=(
                "Switching boundary is unavailable because two complete finite "
                "candidate score decompositions are required."
            ),
        )

    # The completeness check narrows all four values from optional finite values.
    assert bic_eff_a is not None
    assert bic_eff_b is not None
    assert risk_a is not None
    assert risk_b is not None
    delta_bic = bic_eff_b - bic_eff_a
    if risk_a == risk_b:
        if delta_bic == 0.0:
            return SwitchingBoundary(
                candidate_a=candidate_a,
                candidate_b=candidate_b,
                status=SwitchStatus.COINCIDENT,
                switch_c=None,
                current_c=current_c,
                identifiable=False,
                preference_below=None,
                preference_above=None,
                preference_at_current=None,
                interpretation="The candidate score lines coincide for every finite c.",
            )
        preferred = candidate_b if delta_bic < 0.0 else candidate_a
        return SwitchingBoundary(
            candidate_a=candidate_a,
            candidate_b=candidate_b,
            status=SwitchStatus.PARALLEL_NO_SWITCH,
            switch_c=None,
            current_c=current_c,
            identifiable=False,
            preference_below=preferred,
            preference_above=preferred,
            preference_at_current=preferred,
            interpretation=(
                "The predictive components are equal, so the structural ordering "
                "does not switch as c changes."
            ),
        )

    try:
        log_risk_ratio = math.log(risk_a) - math.log(risk_b)
        switch_c = delta_bic * math.log(n_eff) / log_risk_ratio
    except ArithmeticError:
        switch_c = math.nan
    if not math.isfinite(switch_c):
        return SwitchingBoundary(
            candidate_a=candidate_a,
            candidate_b=candidate_b,
            status=SwitchStatus.NOT_AVAILABLE,
            switch_c=None,
            current_c=current_c,
            identifiable=False,
            preference_below=None,
            preference_above=None,
            preference_at_current=None,
            interpretation="The algebraic switching boundary is non-finite.",
        )

    # The score difference C(B)-C(A) has derivative
    # -log(risk(A)/risk(B))/log(n_eff), so these preferences are exact and do
    # not depend on an arbitrary numerical probe distance around c*.
    if log_risk_ratio > 0.0:
        preference_below, preference_above = candidate_a, candidate_b
    else:
        preference_below, preference_above = candidate_b, candidate_a

    if switch_c == 0.0:
        switch_c = 0.0  # Normalize negative zero without changing the boundary.
    status = SwitchStatus.OUTSIDE_NONNEGATIVE_DOMAIN if switch_c < 0.0 else SwitchStatus.FINITE
    interpretation = (
        "The algebraic switching boundary lies outside the declared nonnegative c domain."
        if status is SwitchStatus.OUTSIDE_NONNEGATIVE_DOMAIN
        else "The candidates switch ordering at a finite nonnegative c boundary."
    )
    preference_at_current = (
        None
        if current_c == switch_c
        else preference_below
        if current_c < switch_c
        else preference_above
    )
    return SwitchingBoundary(
        candidate_a=candidate_a,
        candidate_b=candidate_b,
        status=status,
        switch_c=switch_c,
        current_c=current_c,
        identifiable=True,
        preference_below=preference_below,
        preference_above=preference_above,
        preference_at_current=preference_at_current,
        interpretation=interpretation,
    )


def _complete_pairwise_inputs(
    *,
    bic_eff_a: float | None,
    bic_eff_b: float | None,
    risk_a: float | None,
    risk_b: float | None,
) -> bool:
    if bic_eff_a is None or bic_eff_b is None or risk_a is None or risk_b is None:
        return False
    return (
        all(math.isfinite(value) for value in (bic_eff_a, bic_eff_b, risk_a, risk_b))
        and risk_a > 0.0
        and risk_b > 0.0
    )
