from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, TypeAlias

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from riec_guard.contract.models import AuditContract, DatasetProfile, RiecSelection
from riec_guard.contract.schema_loader import load_schema_registry
from riec_guard.riec.design import PreparedDataset, prepare_dataset
from riec_guard.riec.grouped_cv import CandidateEvaluation, evaluate_grouped_candidates
from riec_guard.riec.registry import FROZEN_CANDIDATE_IDS, load_candidate_registry
from riec_guard.riec.scoring import SwitchStatus
from riec_guard.riec.selection import (
    RiecDecision,
    build_canonical_selection,
    compute_riec_decision,
)

FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "stage1"
RUN_ID = "RUN-A1B2C3D4E5F6"
EVIDENCE_ID = "EV-RIEC-123456789ABC"

GoldenRow: TypeAlias = tuple[
    str,
    str,
    int | None,
    float | None,
    float | None,
    float | None,
    float | None,
    str | None,
]

# Values are rounded only at this presentation boundary. They were independently
# recorded from the accepted 80-row public Stage-1 synthetic fixture; production
# calculations retain their unrounded floating-point coordinates.
GOLDEN_CANDIDATE_TABLE: tuple[GoldenRow, ...] = (
    ("M0_intercept", "ok", 1, -582.118539, 0.000656, 1.0, -582.118539, None),
    ("M1_product", "ok", 2, -577.767065, 0.000662, 0.991018, -577.765005, None),
    (
        "M2_product_stream",
        "fit_failed",
        None,
        None,
        None,
        None,
        None,
        "CANDIDATE_DESIGN_RANK_DEFICIENT",
    ),
    ("M3_product_shift", "ok", 3, -573.948515, 0.000697, 0.942075, -573.934898, None),
    (
        "M4_product_stream_shift",
        "fit_failed",
        None,
        None,
        None,
        None,
        None,
        "CANDIDATE_DESIGN_RANK_DEFICIENT",
    ),
    ("M5_product_time", "ok", 3, -573.89323, 0.000657, 0.998684, -573.892929, None),
    (
        "M6_product_stream_shift_time",
        "fit_failed",
        None,
        None,
        None,
        None,
        None,
        "CANDIDATE_DESIGN_RANK_DEFICIENT",
    ),
)


def _json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _round_coordinate(value: float | None) -> float | None:
    return None if value is None else round(value, 6)


def _candidate_table(decision: RiecDecision) -> tuple[GoldenRow, ...]:
    rows: list[GoldenRow] = []
    for item in decision.candidates:
        evaluation = item.evaluation
        full_fit = evaluation.full_fit
        score = item.score
        rows.append(
            (
                evaluation.candidate_id,
                evaluation.status.value,
                None if full_fit is None else full_fit.realized_rank,
                _round_coordinate(None if full_fit is None else full_fit.bic_eff),
                _round_coordinate(evaluation.grouped_risk),
                _round_coordinate(None if score is None else score.xpe),
                _round_coordinate(None if score is None else score.c_score),
                evaluation.failure_code,
            )
        )
    return tuple(rows)


def _run_core() -> tuple[
    PreparedDataset,
    tuple[CandidateEvaluation, ...],
    RiecDecision,
    RiecSelection,
]:
    normalized = (FIXTURE_ROOT / "normalized.csv").read_bytes()
    contract = AuditContract.model_validate(_json_object(FIXTURE_ROOT / "confirmed_contract.json"))
    registry = load_candidate_registry().payload
    dataset = prepare_dataset(normalized, contract)
    evaluations = evaluate_grouped_candidates(
        dataset,
        tuple(registry.candidates),
        max_exact_logo_groups=contract.riec.max_exact_logo_groups,
    )
    decision = compute_riec_decision(
        evaluations,
        c=contract.riec.c,
        near_tie_abs_tol=contract.riec.near_tie_abs_tol,
        near_tie_rel_tol=contract.riec.near_tie_rel_tol,
    )
    selection = build_canonical_selection(
        decision,
        run_id=RUN_ID,
        registry_id=registry.registry_id,
        c=contract.riec.c,
        evidence_id=EVIDENCE_ID,
    )
    return dataset, evaluations, decision, selection


def test_public_stage1_fixture_matches_exact_grouped_riec_golden_table() -> None:
    dataset, evaluations, decision, selection = _run_core()
    normalized = (FIXTURE_ROOT / "normalized.csv").read_bytes()
    profile = DatasetProfile.model_validate(_json_object(FIXTURE_ROOT / "dataset_profile.json"))
    contract = AuditContract.model_validate(_json_object(FIXTURE_ROOT / "confirmed_contract.json"))

    assert dataset.n_rows == profile.row_count == 80
    assert dataset.n_groups == 8
    assert hashlib.sha256(normalized).hexdigest() == profile.dataset_sha256
    assert contract.source.dataset_id == profile.dataset_id
    assert contract.source.dataset_sha256 == profile.dataset_sha256
    assert tuple(evaluation.candidate_id for evaluation in evaluations) == FROZEN_CANDIDATE_IDS
    assert _candidate_table(decision) == GOLDEN_CANDIDATE_TABLE

    assert decision.raw_numeric_winner == "M0_intercept"
    assert decision.winner == "M0_intercept"
    assert decision.runner_up == "M1_product"
    assert _round_coordinate(decision.score_gap) == 4.353534
    assert decision.near_tie is False
    assert decision.equivalence_set == ("M0_intercept",)
    assert decision.switching_boundary.status is SwitchStatus.OUTSIDE_NONNEGATIVE_DOMAIN
    assert decision.switching_boundary.candidate_a == "M0_intercept"
    assert decision.switching_boundary.candidate_b == "M1_product"
    assert _round_coordinate(decision.switching_boundary.switch_c) == -2113.342913

    canonical = selection.to_canonical_dict()
    assert RiecSelection.model_validate(canonical) == selection
    Draft202012Validator(
        load_schema_registry().lookup("riec_selection").validation_schema(),
        format_checker=FormatChecker(),
    ).validate(canonical)


def test_public_stage1_grouped_riec_repeated_execution_is_identical() -> None:
    first = _run_core()
    second = _run_core()

    assert first == second
    assert _candidate_table(first[2]) == GOLDEN_CANDIDATE_TABLE
    assert first[3].to_canonical_json() == second[3].to_canonical_json()
