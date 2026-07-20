from __future__ import annotations

import math
from dataclasses import dataclass

from riec_guard.contract.models import (
    CandidateLedgerEntry,
    CandidateStatus,
    PairwiseSwitch,
    RiecSelection,
    SelectionDecisionStatus,
)
from riec_guard.riec.design import RiecReasonCode
from riec_guard.riec.grouped_cv import CandidateEvaluation, EvaluationStatus
from riec_guard.riec.registry import FROZEN_BASELINE_CANDIDATE_ID, FROZEN_CANDIDATE_IDS
from riec_guard.riec.scoring import (
    RiecScore,
    ScoringFailure,
    SwitchingBoundary,
    TiePolicy,
    score_candidate,
    switching_boundary,
)


class SelectionFailure(ValueError):
    """Fail-closed selection error carrying a stable public reason code."""

    def __init__(self, code: RiecReasonCode, message: str) -> None:
        super().__init__(message[:300])
        self.code = code


@dataclass(frozen=True, slots=True)
class ScoredEvaluation:
    evaluation: CandidateEvaluation
    score: RiecScore | None
    score_failure_code: str | None


@dataclass(frozen=True, slots=True)
class RiecDecision:
    candidates: tuple[ScoredEvaluation, ...]
    raw_numeric_winner: str
    winner: str | None
    runner_up: str | None
    score_gap: float | None
    near_tie: bool
    equivalence_set: tuple[str, ...]
    switching_boundary: SwitchingBoundary
    tie_threshold: float


def compute_riec_decision(
    evaluations: tuple[CandidateEvaluation, ...],
    *,
    c: float,
    near_tie_abs_tol: float,
    near_tie_rel_tol: float,
) -> RiecDecision:
    """Score and rank a complete frozen evaluation ledger without dropping failures."""

    by_id = {evaluation.candidate_id: evaluation for evaluation in evaluations}
    if len(by_id) != len(evaluations) or set(by_id) != set(FROZEN_CANDIDATE_IDS):
        raise SelectionFailure(
            RiecReasonCode.RIEC_SELECTION_UNAVAILABLE,
            "Selection requires exactly the frozen seven-candidate ledger.",
        )
    ordered = tuple(by_id[candidate_id] for candidate_id in FROZEN_CANDIDATE_IDS)
    baseline = by_id[FROZEN_BASELINE_CANDIDATE_ID]
    if (
        baseline.status is not EvaluationStatus.OK
        or baseline.full_fit is None
        or baseline.grouped_risk is None
        or not math.isfinite(baseline.grouped_risk)
        or baseline.grouped_risk <= 0.0
    ):
        raise SelectionFailure(
            RiecReasonCode.RIEC_BASELINE_INELIGIBLE,
            "The frozen M0 baseline is unavailable for normalized RIEC scoring.",
        )

    scored: list[ScoredEvaluation] = []
    for evaluation in ordered:
        if (
            evaluation.status is not EvaluationStatus.OK
            or evaluation.full_fit is None
            or evaluation.grouped_risk is None
        ):
            scored.append(
                ScoredEvaluation(
                    evaluation=evaluation,
                    score=None,
                    score_failure_code=evaluation.failure_code,
                )
            )
            continue
        try:
            score = score_candidate(
                bic_eff=evaluation.full_fit.bic_eff,
                risk=evaluation.grouped_risk,
                baseline_risk=baseline.grouped_risk,
                n_eff=evaluation.n_rows,
                c=c,
            )
        except ScoringFailure:
            scored.append(
                ScoredEvaluation(
                    evaluation=evaluation,
                    score=None,
                    score_failure_code=RiecReasonCode.RIEC_SCORE_UNAVAILABLE.value,
                )
            )
        else:
            scored.append(
                ScoredEvaluation(evaluation=evaluation, score=score, score_failure_code=None)
            )

    frozen_index = {candidate_id: index for index, candidate_id in enumerate(FROZEN_CANDIDATE_IDS)}
    ranked = sorted(
        (item for item in scored if item.score is not None),
        key=lambda item: (
            item.score.c_score if item.score is not None else math.inf,
            frozen_index[item.evaluation.candidate_id],
        ),
    )
    if not ranked:
        raise SelectionFailure(
            RiecReasonCode.RIEC_SELECTION_UNAVAILABLE,
            "No candidate has a finite exact RIEC score.",
        )
    raw_winner = ranked[0]
    assert raw_winner.score is not None
    runner = ranked[1] if len(ranked) > 1 else None
    runner_score = runner.score if runner is not None else None
    score_gap = (
        runner_score.c_score - raw_winner.score.c_score if runner_score is not None else None
    )
    if score_gap is not None and (not math.isfinite(score_gap) or score_gap < 0.0):
        raise SelectionFailure(
            RiecReasonCode.RIEC_SELECTION_UNAVAILABLE,
            "The ranked score gap is invalid.",
        )

    try:
        tie_policy = TiePolicy(near_tie_abs_tol, near_tie_rel_tol)
        tie_threshold = tie_policy.threshold(raw_winner.score.c_score)
        equivalent_ids = {
            item.evaluation.candidate_id
            for item in ranked
            if item.score is not None
            and tie_policy.is_equivalent(
                score=item.score.c_score,
                winner_score=raw_winner.score.c_score,
            )
        }
    except ScoringFailure:
        raise SelectionFailure(
            RiecReasonCode.RIEC_SELECTION_UNAVAILABLE,
            "The confirmed tie policy cannot be applied.",
        ) from None
    equivalence_set = tuple(
        candidate_id for candidate_id in FROZEN_CANDIDATE_IDS if candidate_id in equivalent_ids
    )
    near_tie = len(equivalence_set) > 1
    winner = None if near_tie else raw_winner.evaluation.candidate_id

    boundary = switching_boundary(
        candidate_a=raw_winner.evaluation.candidate_id,
        candidate_b=runner.evaluation.candidate_id if runner is not None else None,
        bic_eff_a=raw_winner.score.bic_eff,
        bic_eff_b=runner_score.bic_eff if runner_score is not None else None,
        risk_a=raw_winner.score.risk,
        risk_b=runner_score.risk if runner_score is not None else None,
        n_eff=raw_winner.evaluation.n_rows,
        current_c=c,
    )
    return RiecDecision(
        candidates=tuple(scored),
        raw_numeric_winner=raw_winner.evaluation.candidate_id,
        winner=winner,
        runner_up=runner.evaluation.candidate_id if runner is not None else None,
        score_gap=score_gap,
        near_tie=near_tie,
        equivalence_set=equivalence_set,
        switching_boundary=boundary,
        tie_threshold=tie_threshold,
    )


def build_canonical_selection(
    decision: RiecDecision,
    *,
    run_id: str,
    registry_id: str,
    c: float,
    evidence_id: str,
) -> RiecSelection:
    """Project internal diagnostics into the frozen canonical selection schema."""

    candidate_ledger = tuple(
        _canonical_candidate(item, evidence_id=evidence_id) for item in decision.candidates
    )
    pairwise_switches: tuple[PairwiseSwitch, ...] = ()
    if decision.runner_up is not None:
        boundary = decision.switching_boundary
        interpretation = (
            f"status={boundary.status.value}; "
            f"preferred_below={boundary.preference_below or 'not_available'}; "
            f"preferred_above={boundary.preference_above or 'not_available'}; "
            f"current_c={boundary.current_c}; "
            f"preferred_at_current={boundary.preference_at_current or 'tie_or_unavailable'}. "
            f"{boundary.interpretation}"
        )
        pairwise_switches = (
            PairwiseSwitch.model_validate(
                {
                    "candidate_a": boundary.candidate_a,
                    "candidate_b": decision.runner_up,
                    "switch_c": boundary.switch_c,
                    "identifiable": boundary.identifiable,
                    "interpretation": interpretation,
                    "evidence_ids": (evidence_id,),
                }
            ),
        )
    selection = RiecSelection.model_validate(
        {
            "schema_version": "1.0.0",
            "run_id": run_id,
            "registry_id": registry_id,
            "baseline_candidate_id": FROZEN_BASELINE_CANDIDATE_ID,
            "risk_aggregation": "row_weighted_grouped_mse",
            "c": c,
            "candidate_ledger": candidate_ledger,
            "raw_numeric_winner": decision.raw_numeric_winner,
            "runner_up": decision.runner_up,
            "score_gap": decision.score_gap,
            "decision_status": (
                SelectionDecisionStatus.NEAR_TIE
                if decision.near_tie
                else SelectionDecisionStatus.SELECTED
            ),
            "equivalence_set": decision.equivalence_set,
            "pairwise_switches": pairwise_switches,
            "evidence_ids": (evidence_id,),
        }
    )
    selection.to_canonical_dict()
    return selection


def _canonical_candidate(
    item: ScoredEvaluation,
    *,
    evidence_id: str,
) -> CandidateLedgerEntry:
    evaluation = item.evaluation
    full_fit = evaluation.full_fit
    score = item.score
    status = _canonical_status(evaluation.status)
    failure_code = evaluation.failure_code
    if evaluation.status is EvaluationStatus.OK and score is None:
        # The frozen schema has no score-failed state. INFEASIBLE is the honest
        # projection because fit/prediction succeeded but the row cannot enter ranking.
        status = CandidateStatus.INFEASIBLE
        failure_code = item.score_failure_code or RiecReasonCode.RIEC_SCORE_UNAVAILABLE.value
    return CandidateLedgerEntry.model_validate(
        {
            "candidate_id": evaluation.candidate_id,
            "status": status,
            "parameter_count": full_fit.realized_rank if full_fit is not None else None,
            "bic_eff": full_fit.bic_eff if full_fit is not None else None,
            "grouped_risk": evaluation.grouped_risk,
            "group_balanced_risk": evaluation.group_balanced_risk,
            "xpe": score.xpe if score is not None else None,
            "c_score": score.c_score if score is not None else None,
            "n_rows": evaluation.n_rows,
            "n_groups": evaluation.n_groups,
            "failure_code": failure_code,
            "evidence_ids": (evidence_id,),
        }
    )


def _canonical_status(status: EvaluationStatus) -> CandidateStatus:
    return {
        EvaluationStatus.OK: CandidateStatus.OK,
        EvaluationStatus.INELIGIBLE: CandidateStatus.INFEASIBLE,
        EvaluationStatus.FIT_FAILED: CandidateStatus.FIT_FAILED,
        EvaluationStatus.PREDICTION_FAILED: CandidateStatus.PREDICTION_FAILED,
    }[status]


__all__ = [
    "RiecDecision",
    "ScoredEvaluation",
    "SelectionFailure",
    "build_canonical_selection",
    "compute_riec_decision",
]
