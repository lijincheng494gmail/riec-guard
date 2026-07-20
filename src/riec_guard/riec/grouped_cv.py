from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum

from riec_guard.contract.models import CandidateDefinition
from riec_guard.riec.design import (
    DesignFailure,
    PreparedDataset,
    RiecReasonCode,
    build_prediction_design,
    build_training_design,
    candidate_semantics_available,
)
from riec_guard.riec.fit import (
    FitFailure,
    OlsFitResult,
    fit_linear_model,
    fit_ols,
    predict_ols,
)
from riec_guard.riec.registry import FROZEN_CANDIDATE_IDS, load_candidate_registry


class EvaluationStatus(StrEnum):
    OK = "ok"
    INELIGIBLE = "ineligible"
    FIT_FAILED = "fit_failed"
    PREDICTION_FAILED = "prediction_failed"


@dataclass(frozen=True, slots=True)
class FoldDiagnostic:
    group_token: str
    n_train: int
    n_test: int
    status: EvaluationStatus
    sse: float | None
    mse: float | None
    failure_code: str | None


@dataclass(frozen=True, slots=True)
class CandidateEvaluation:
    candidate_id: str
    status: EvaluationStatus
    full_fit: OlsFitResult | None
    grouped_risk: float | None
    group_balanced_risk: float | None
    n_rows: int
    n_groups: int
    folds: tuple[FoldDiagnostic, ...]
    failure_code: str | None


def exact_logo_plan(
    dataset: PreparedDataset,
) -> tuple[tuple[str, tuple[int, ...], tuple[int, ...]], ...]:
    """Return deterministic, exhaustive, disjoint leave-one-group-out folds."""

    group_tokens = tuple(sorted(set(dataset.group_tokens)))
    all_indices = tuple(range(dataset.n_rows))
    folds: list[tuple[str, tuple[int, ...], tuple[int, ...]]] = []
    tested: list[int] = []
    for token in group_tokens:
        test = tuple(index for index in all_indices if dataset.group_tokens[index] == token)
        train = tuple(index for index in all_indices if dataset.group_tokens[index] != token)
        if not train:
            raise DesignFailure(
                RiecReasonCode.CANDIDATE_EMPTY_TRAIN_FOLD,
                "An exact grouped training fold is empty.",
            )
        if not test:
            raise DesignFailure(
                RiecReasonCode.CANDIDATE_EMPTY_TEST_FOLD,
                "An exact grouped test fold is empty.",
            )
        if set(train) & set(test) or set(train) | set(test) != set(all_indices):
            raise DesignFailure(
                RiecReasonCode.RIEC_INVALID_DEPLOYMENT_GROUP,
                "Exact grouped folds are not disjoint and exhaustive.",
            )
        tested.extend(test)
        folds.append((token, train, test))
    if sorted(tested) != list(all_indices):
        raise DesignFailure(
            RiecReasonCode.RIEC_INVALID_DEPLOYMENT_GROUP,
            "Exact grouped folds do not test every row exactly once.",
        )
    return tuple(folds)


def evaluate_grouped_candidates(
    dataset: PreparedDataset,
    candidates: tuple[CandidateDefinition, ...],
    *,
    max_exact_logo_groups: int,
) -> tuple[CandidateEvaluation, ...]:
    """Evaluate the frozen library with exact leave-one-deployment-group-out CV."""

    actual_groups = set(dataset.group_keys)
    token_pairs = set(zip(dataset.group_keys, dataset.group_tokens, strict=True))
    if (
        dataset.n_rows != len(dataset.response)
        or dataset.n_rows != len(dataset.group_keys)
        or dataset.n_rows != len(dataset.group_tokens)
        or dataset.n_groups != len(actual_groups)
        or len(token_pairs) != len(actual_groups)
        or len(set(dataset.group_tokens)) != len(actual_groups)
    ):
        raise DesignFailure(
            RiecReasonCode.RIEC_INVALID_DEPLOYMENT_GROUP,
            "Prepared deployment-group metadata is inconsistent.",
        )
    if dataset.n_groups < 2:
        raise DesignFailure(
            RiecReasonCode.RIEC_INSUFFICIENT_GROUPS,
            "Exact grouped evaluation requires at least two deployment groups.",
        )
    if dataset.n_groups > max_exact_logo_groups:
        raise DesignFailure(
            RiecReasonCode.RIEC_TOO_MANY_GROUPS_EXACT_LOGO,
            "Deployment-group count exceeds the confirmed exact-LOGO limit.",
        )
    by_id = {candidate.candidate_id: candidate for candidate in candidates}
    trusted_candidates = tuple(load_candidate_registry().payload.candidates)
    if (
        tuple(by_id) != FROZEN_CANDIDATE_IDS
        or len(by_id) != len(candidates)
        or tuple(candidate.to_canonical_dict() for candidate in candidates)
        != tuple(candidate.to_canonical_dict() for candidate in trusted_candidates)
    ):
        raise DesignFailure(
            RiecReasonCode.RIEC_REGISTRY_MISMATCH,
            "Candidate definitions do not match the frozen library order.",
        )
    folds = exact_logo_plan(dataset)
    return tuple(
        _evaluate_candidate(dataset, by_id[candidate_id], folds)
        for candidate_id in FROZEN_CANDIDATE_IDS
    )


def _evaluate_candidate(
    dataset: PreparedDataset,
    candidate: CandidateDefinition,
    folds: tuple[tuple[str, tuple[int, ...], tuple[int, ...]], ...],
) -> CandidateEvaluation:
    requirements = candidate.feasibility_requirements
    if dataset.n_rows < requirements.min_rows:
        return _failed_evaluation(
            dataset,
            candidate.candidate_id,
            EvaluationStatus.INELIGIBLE,
            RiecReasonCode.CANDIDATE_INSUFFICIENT_SUPPORT,
        )
    if dataset.n_groups < requirements.min_groups:
        return _failed_evaluation(
            dataset,
            candidate.candidate_id,
            EvaluationStatus.INELIGIBLE,
            RiecReasonCode.RIEC_INSUFFICIENT_GROUPS,
        )
    available, reason = candidate_semantics_available(dataset, candidate)
    if not available:
        return _failed_evaluation(
            dataset,
            candidate.candidate_id,
            EvaluationStatus.INELIGIBLE,
            reason or RiecReasonCode.CANDIDATE_REQUIRED_SEMANTIC_MISSING,
        )

    all_indices = tuple(range(dataset.n_rows))
    try:
        full_design = build_training_design(dataset, candidate, all_indices)
    except DesignFailure as error:
        return _failed_evaluation(
            dataset,
            candidate.candidate_id,
            EvaluationStatus.INELIGIBLE,
            error.code,
        )
    try:
        full_fit = fit_ols(full_design.values, full_design.response, n_eff=dataset.n_rows)
    except FitFailure as error:
        return _failed_evaluation(
            dataset,
            candidate.candidate_id,
            EvaluationStatus.FIT_FAILED,
            _fit_reason(error),
        )

    diagnostics: list[FoldDiagnostic] = []
    for group_token, train_indices, test_indices in folds:
        try:
            training = build_training_design(dataset, candidate, train_indices)
            test = build_prediction_design(dataset, training.specification, test_indices)
            fold_fit = fit_linear_model(training.values, training.response)
            predictions = predict_ols(fold_fit, test.values)
            try:
                squared_errors = tuple(
                    (observed - predicted) ** 2
                    for observed, predicted in zip(test.response, predictions, strict=True)
                )
                sse = math.fsum(squared_errors)
                mse = sse / len(test.response)
            except ArithmeticError as error:
                raise DesignFailure(
                    RiecReasonCode.CANDIDATE_NONFINITE_RESULT,
                    "A grouped prediction diagnostic is invalid.",
                ) from error
            if not math.isfinite(sse) or not math.isfinite(mse) or sse < 0.0 or mse < 0.0:
                raise DesignFailure(
                    RiecReasonCode.CANDIDATE_NONFINITE_RESULT,
                    "A grouped prediction diagnostic is invalid.",
                )
        except (DesignFailure, FitFailure) as error:
            failure_code = (
                error.code.value if isinstance(error, DesignFailure) else _fit_reason(error).value
            )
            diagnostics.append(
                FoldDiagnostic(
                    group_token=group_token,
                    n_train=len(train_indices),
                    n_test=len(test_indices),
                    status=EvaluationStatus.PREDICTION_FAILED,
                    sse=None,
                    mse=None,
                    failure_code=failure_code,
                )
            )
            continue
        diagnostics.append(
            FoldDiagnostic(
                group_token=group_token,
                n_train=len(train_indices),
                n_test=len(test_indices),
                status=EvaluationStatus.OK,
                sse=sse,
                mse=mse,
                failure_code=None,
            )
        )

    failed_folds = tuple(item for item in diagnostics if item.status is not EvaluationStatus.OK)
    if failed_folds:
        return CandidateEvaluation(
            candidate_id=candidate.candidate_id,
            status=EvaluationStatus.PREDICTION_FAILED,
            full_fit=full_fit,
            grouped_risk=None,
            group_balanced_risk=None,
            n_rows=dataset.n_rows,
            n_groups=dataset.n_groups,
            folds=tuple(diagnostics),
            failure_code=failed_folds[0].failure_code,
        )
    successful_sses = tuple(item.sse for item in diagnostics if item.sse is not None)
    successful_mses = tuple(item.mse for item in diagnostics if item.mse is not None)
    total_test_rows = sum(item.n_test for item in diagnostics)
    grouped_risk = math.fsum(successful_sses) / total_test_rows
    group_balanced_risk = math.fsum(successful_mses) / len(successful_mses)
    if (
        total_test_rows != dataset.n_rows
        or not math.isfinite(grouped_risk)
        or not math.isfinite(group_balanced_risk)
        or grouped_risk < 0.0
        or group_balanced_risk < 0.0
    ):
        return CandidateEvaluation(
            candidate_id=candidate.candidate_id,
            status=EvaluationStatus.PREDICTION_FAILED,
            full_fit=full_fit,
            grouped_risk=None,
            group_balanced_risk=None,
            n_rows=dataset.n_rows,
            n_groups=dataset.n_groups,
            folds=tuple(diagnostics),
            failure_code=RiecReasonCode.CANDIDATE_NONFINITE_RESULT.value,
        )
    return CandidateEvaluation(
        candidate_id=candidate.candidate_id,
        status=EvaluationStatus.OK,
        full_fit=full_fit,
        grouped_risk=grouped_risk,
        group_balanced_risk=group_balanced_risk,
        n_rows=dataset.n_rows,
        n_groups=dataset.n_groups,
        folds=tuple(diagnostics),
        failure_code=None,
    )


def _failed_evaluation(
    dataset: PreparedDataset,
    candidate_id: str,
    status: EvaluationStatus,
    reason: RiecReasonCode,
) -> CandidateEvaluation:
    return CandidateEvaluation(
        candidate_id=candidate_id,
        status=status,
        full_fit=None,
        grouped_risk=None,
        group_balanced_risk=None,
        n_rows=dataset.n_rows,
        n_groups=dataset.n_groups,
        folds=(),
        failure_code=reason.value,
    )


def _fit_reason(error: FitFailure) -> RiecReasonCode:
    if error.code == RiecReasonCode.CANDIDATE_DESIGN_RANK_DEFICIENT.value:
        return RiecReasonCode.CANDIDATE_DESIGN_RANK_DEFICIENT
    if error.code == RiecReasonCode.CANDIDATE_NONFINITE_RESULT.value:
        return RiecReasonCode.CANDIDATE_NONFINITE_RESULT
    return RiecReasonCode.CANDIDATE_FIT_FAILED


__all__ = [
    "CandidateEvaluation",
    "EvaluationStatus",
    "FoldDiagnostic",
    "evaluate_grouped_candidates",
    "exact_logo_plan",
]
