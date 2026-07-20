from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

import pytest

from riec_guard.contract.models import AuditContract, CandidateDefinition
from riec_guard.riec.design import (
    DesignFailure,
    PreparedDataset,
    RiecReasonCode,
    build_prediction_design,
    build_training_design,
    candidate_semantics_available,
    prepare_dataset,
)
from riec_guard.riec.grouped_cv import exact_logo_plan
from riec_guard.riec.registry import FROZEN_CANDIDATE_IDS, load_candidate_registry

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_EXAMPLE = REPOSITORY_ROOT / "schemas" / "examples" / "audit_contract.example.json"
HEADER = (
    "quantity_ml",
    "product_id",
    "batch_id",
    "timestamp",
    "stream_id",
    "shift_id",
)
ROWS = (
    ("13", "B", "g2", "2026-01-01T05:00:00+02:00", "S2", "night"),
    ("10", "A", "g1", "2026-01-01T00:00:00Z", "S1", "day"),
    ("12", "B", "g1", "2026-01-01T02:00:00Z", "S1", "night"),
    ("11", "A", "g2", "2026-01-01T01:00:00Z", "S2", "day"),
    ("14", "A", "g3", "2026-01-01T04:00:00Z", "S1", "night"),
    ("15", "B", "g3", "2026-01-01T05:00:00Z", "S2", "day"),
)


def _csv(header: tuple[str, ...], rows: tuple[tuple[str, ...], ...]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(header)
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def _contract(
    header: tuple[str, ...],
    *,
    row_count: int,
    stream_confirmed: bool = True,
) -> AuditContract:
    value: dict[str, Any] = json.loads(CONTRACT_EXAMPLE.read_text(encoding="utf-8"))
    source = value["source"]
    mapping = value["column_mapping"]
    grouping = value["grouping"]
    ordering = value["ordering"]
    assert isinstance(source, dict)
    assert isinstance(mapping, dict)
    assert isinstance(grouping, dict)
    assert isinstance(ordering, dict)

    source["row_count"] = row_count
    source["column_count"] = len(header)
    for semantic, column in (
        ("quantity", "quantity_ml"),
        ("product", "product_id"),
        ("deployment_group", "batch_id"),
        ("time", "timestamp"),
        ("stream", "stream_id"),
        ("shift", "shift_id"),
    ):
        reference = mapping[semantic]
        assert isinstance(reference, dict)
        available = column in header and (semantic != "stream" or stream_confirmed)
        reference["column"] = column if available else None
        reference["confirmed"] = available

    grouping["deployment_group_columns"] = ["batch_id"]
    grouping["nested_context_columns"] = [
        column for column in ("stream_id", "shift_id") if column in header
    ]
    ordering["time_column"] = "timestamp" if "timestamp" in header else None
    return AuditContract.model_validate(value)


def _candidates() -> dict[str, CandidateDefinition]:
    candidates = load_candidate_registry().payload.candidates
    assert tuple(candidate.candidate_id for candidate in candidates) == FROZEN_CANDIDATE_IDS
    return {candidate.candidate_id: candidate for candidate in candidates}


def test_treatment_coding_is_lexical_stable_and_uses_first_level_as_reference() -> None:
    dataset = prepare_dataset(_csv(HEADER, ROWS), _contract(HEADER, row_count=len(ROWS)))
    candidate = _candidates()["M4_product_stream_shift"]

    design = build_training_design(dataset, candidate, tuple(reversed(range(len(ROWS)))))
    repeated = build_training_design(dataset, candidate, tuple(range(len(ROWS))))

    assert design == repeated
    assert design.specification.column_names == (
        "intercept",
        "product[1]",
        "stream[1]",
        "shift[1]",
    )
    assert tuple(
        (encoding.term, encoding.levels, encoding.reference_level)
        for encoding in design.specification.categorical_encodings
    ) == (
        ("product", ("A", "B"), "A"),
        ("stream", ("S1", "S2"), "S1"),
        ("shift", ("day", "night"), "day"),
    )
    by_source_row = dict(zip(design.row_indices, design.values, strict=True))
    assert by_source_row == {
        0: (1.0, 1.0, 1.0, 1.0),
        1: (1.0, 0.0, 0.0, 0.0),
        2: (1.0, 1.0, 0.0, 1.0),
        3: (1.0, 0.0, 1.0, 0.0),
        4: (1.0, 0.0, 0.0, 1.0),
        5: (1.0, 1.0, 1.0, 0.0),
    }


def test_time_is_elapsed_hours_from_one_dataset_wide_utc_origin() -> None:
    dataset = prepare_dataset(_csv(HEADER, ROWS), _contract(HEADER, row_count=len(ROWS)))
    assert dataset.time_hours == (3.0, 0.0, 2.0, 1.0, 4.0, 5.0)

    design = build_training_design(
        dataset,
        _candidates()["M5_product_time"],
        tuple(range(len(ROWS))),
    )
    assert design.specification.column_names == (
        "intercept",
        "product[1]",
        "time_elapsed_hours",
    )
    elapsed_by_source_row = {
        index: row[-1] for index, row in zip(design.row_indices, design.values, strict=True)
    }
    assert elapsed_by_source_row == {0: 3.0, 1: 0.0, 2: 2.0, 3: 1.0, 4: 4.0, 5: 5.0}


def test_exact_logo_is_disjoint_exhaustive_and_holds_out_each_group_once() -> None:
    dataset = prepare_dataset(_csv(HEADER, ROWS), _contract(HEADER, row_count=len(ROWS)))
    folds = exact_logo_plan(dataset)
    baseline = _candidates()["M0_intercept"]

    assert len(folds) == dataset.n_groups == 3
    tested: list[int] = []
    for token, train, test in folds:
        assert set(train).isdisjoint(test)
        assert set(train) | set(test) == set(range(dataset.n_rows))
        assert {dataset.group_tokens[index] for index in test} == {token}
        assert token not in {dataset.group_tokens[index] for index in train}
        assert len({dataset.group_keys[index] for index in test}) == 1
        tested.extend(test)

        training = build_training_design(dataset, baseline, train)
        prediction = build_prediction_design(dataset, training.specification, test)
        assert set(training.row_indices) == set(train)
        assert set(prediction.row_indices) == set(test)

    assert sorted(tested) == list(range(dataset.n_rows))


def test_missing_stream_only_disables_stream_dependent_frozen_candidates() -> None:
    header = tuple(column for column in HEADER if column != "stream_id")
    rows = tuple(
        tuple(value for index, value in enumerate(row) if HEADER[index] != "stream_id")
        for row in ROWS
    )
    dataset = prepare_dataset(
        _csv(header, rows),
        _contract(header, row_count=len(rows), stream_confirmed=False),
    )
    candidates = _candidates()

    for candidate_id in (
        "M2_product_stream",
        "M4_product_stream_shift",
        "M6_product_stream_shift_time",
    ):
        assert candidate_semantics_available(dataset, candidates[candidate_id]) == (
            False,
            RiecReasonCode.CANDIDATE_REQUIRED_SEMANTIC_MISSING,
        )
    for candidate_id in ("M0_intercept", "M1_product", "M3_product_shift", "M5_product_time"):
        assert candidate_semantics_available(dataset, candidates[candidate_id]) == (True, None)


def test_held_out_unseen_level_fails_without_reference_level_fallback() -> None:
    rows = (
        ("10", "A", "g1", "2026-01-01T00:00:00Z", "S1", "day"),
        ("11", "B", "g1", "2026-01-01T01:00:00Z", "S2", "night"),
        ("12", "A", "g2", "2026-01-01T02:00:00Z", "S1", "night"),
        ("13", "B", "g2", "2026-01-01T03:00:00Z", "S2", "day"),
        ("14", "C", "g3", "2026-01-01T04:00:00Z", "S1", "day"),
        ("15", "C", "g3", "2026-01-01T05:00:00Z", "S2", "night"),
    )
    dataset = prepare_dataset(_csv(HEADER, rows), _contract(HEADER, row_count=len(rows)))
    product = _candidates()["M1_product"]
    product_values = dataset.product.values
    assert product_values is not None
    _, train, test = next(
        fold
        for fold in exact_logo_plan(dataset)
        if {product_values[index] for index in fold[2]} == {"C"}
    )
    training = build_training_design(dataset, product, train)

    assert training.specification.categorical_encodings[0].levels == ("A", "B")
    with pytest.raises(DesignFailure) as captured:
        build_prediction_design(dataset, training.specification, test)
    assert captured.value.code is RiecReasonCode.CANDIDATE_UNSEEN_LEVEL


@pytest.mark.parametrize("invalid", ["nan", "inf", "-inf"])
def test_nonfinite_quantity_fails_closed(invalid: str) -> None:
    rows = (
        (invalid, "A", "g1", "2026-01-01T00:00:00Z", "S1", "day"),
        ("10", "B", "g2", "2026-01-01T01:00:00Z", "S2", "night"),
    )
    with pytest.raises(DesignFailure) as captured:
        prepare_dataset(_csv(HEADER, rows), _contract(HEADER, row_count=len(rows)))
    assert captured.value.code is RiecReasonCode.RIEC_INVALID_QUANTITY


def test_design_is_invariant_to_row_permutation_and_group_label_renaming() -> None:
    contract = _contract(HEADER, row_count=len(ROWS))
    candidate = _candidates()["M4_product_stream_shift"]
    original = prepare_dataset(_csv(HEADER, ROWS), contract)
    permuted_rows = tuple(ROWS[index] for index in (4, 1, 5, 0, 3, 2))
    permuted = prepare_dataset(_csv(HEADER, permuted_rows), contract)

    original_design = build_training_design(original, candidate, tuple(range(len(ROWS))))
    permuted_design = build_training_design(permuted, candidate, tuple(range(len(ROWS))))
    assert original_design.values == permuted_design.values
    assert original_design.response == permuted_design.response
    assert original_design.specification == permuted_design.specification

    renaming = {"g1": "renamed-z", "g2": "renamed-a", "g3": "renamed-m"}
    renamed_rows = tuple((*row[:2], renaming[row[2]], *row[3:]) for row in ROWS)
    renamed = prepare_dataset(_csv(HEADER, renamed_rows), contract)
    renamed_design = build_training_design(renamed, candidate, tuple(range(len(ROWS))))
    assert renamed_design.values == original_design.values
    assert renamed_design.response == original_design.response
    assert renamed_design.specification == original_design.specification

    def memberships(
        dataset: PreparedDataset,
    ) -> list[tuple[tuple[int, ...], tuple[int, ...]]]:
        return sorted((train, test) for _, train, test in exact_logo_plan(dataset))

    assert memberships(renamed) == memberships(original)
