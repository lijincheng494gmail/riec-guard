from __future__ import annotations

import csv
import io
import json
import math
import re
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from riec_guard.contract.canonicalize import (
    CONFIRMATION_FIELD_ORDER,
    canonicalize_audit_contract,
    compute_contract_hash,
)
from riec_guard.contract.models import AuditContract, CandidateStatus, DatasetProfile, RiecSelection
from riec_guard.contract.profiler import profile_dataset
from riec_guard.contract.validator import analysis_is_permitted, validate_audit_contract
from riec_guard.domain.source import SourceRepository
from riec_guard.errors import ErrorEnvelope
from riec_guard.evidence.ids import verify_evidence_item
from riec_guard.evidence.ledger import EvidenceLedgerBuilder
from riec_guard.evidence.models import EvidenceComponent, EvidenceKind, EvidenceStatus
from riec_guard.riec.design import build_prediction_design, build_training_design, prepare_dataset
from riec_guard.riec.fit import fit_ols, predict_ols
from riec_guard.riec.grouped_cv import EvaluationStatus
from riec_guard.riec.registry import FROZEN_CANDIDATE_IDS, load_run_registry_snapshot
from riec_guard.riec.service import RiecCoreResult, run_grouped_riec_core
from riec_guard.settings import RuntimeSettings

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
STAGE1_ROOT = REPOSITORY_ROOT / "tests" / "golden" / "fixtures" / "stage1"
HEADER = ("quantity", "product", "batch_id", "timestamp", "stream", "shift", "row_sequence")


@dataclass(frozen=True, slots=True)
class _Context:
    repository: SourceRepository
    run_id: str
    source_id: str
    normalized: bytes
    profile: DatasetProfile
    contract: AuditContract


def _csv(rows: tuple[tuple[str, ...], ...], header: tuple[str, ...] = HEADER) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(header)
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def _product_rows(
    *,
    group_sizes: tuple[int, ...] = (20, 20, 20, 20),
    group_labels: tuple[str, ...] | None = None,
    group_offsets: tuple[float, ...] | None = None,
    constant_quantity: bool = False,
    group_unique_stream: bool = False,
) -> tuple[tuple[str, ...], ...]:
    labels = group_labels or tuple(f"batch_{index + 1}" for index in range(len(group_sizes)))
    offsets = group_offsets or (0.15, -0.10, 0.05, -0.10)[: len(group_sizes)]
    assert len(labels) == len(group_sizes) == len(offsets)
    started = datetime(2026, 7, 20, tzinfo=timezone.utc)
    rows: list[tuple[str, ...]] = []
    sequence = 0
    noise = (-0.11, 0.04, 0.09, -0.03, 0.01)
    for group_index, (label, size, group_offset) in enumerate(
        zip(labels, group_sizes, offsets, strict=True)
    ):
        for local_index in range(size):
            product = "product_B" if local_index % 2 else "product_A"
            stream = (
                f"group_stream_{group_index + 1}"
                if group_unique_stream
                else f"stream_{local_index % 4 + 1}"
            )
            shift = "night" if (local_index // 2) % 2 else "day"
            quantity = (
                0.0
                if constant_quantity
                else 100.0
                + (8.0 if product == "product_B" else 0.0)
                + group_offset
                + noise[(local_index + 2 * group_index) % len(noise)]
            )
            timestamp = started + timedelta(minutes=sequence)
            rows.append(
                (
                    f"{quantity:.6f}",
                    product,
                    label,
                    timestamp.isoformat().replace("+00:00", "Z"),
                    stream,
                    shift,
                    str(sequence + 1),
                )
            )
            sequence += 1
    return tuple(rows)


def _contract_for_profile(
    profile: DatasetProfile,
    *,
    header: tuple[str, ...],
    stream_confirmed: bool,
) -> AuditContract:
    value: dict[str, Any] = json.loads(
        (STAGE1_ROOT / "confirmed_contract.json").read_text(encoding="utf-8")
    )
    source = value["source"]
    mapping = value["column_mapping"]
    grouping = value["grouping"]
    ordering = value["ordering"]
    confirmation = value["confirmation"]
    assert isinstance(source, dict)
    assert isinstance(mapping, dict)
    assert isinstance(grouping, dict)
    assert isinstance(ordering, dict)
    assert isinstance(confirmation, dict)

    source.update(
        {
            "dataset_id": profile.dataset_id,
            "dataset_sha256": profile.dataset_sha256,
            "row_count": profile.row_count,
            "column_count": len(profile.column_profiles),
            "filename_display": "macro01_public_synthetic.csv",
        }
    )
    for semantic, column in (
        ("quantity", "quantity"),
        ("product", "product"),
        ("deployment_group", "batch_id"),
        ("time", "timestamp"),
        ("stream", "stream"),
        ("shift", "shift"),
    ):
        reference = mapping[semantic]
        assert isinstance(reference, dict)
        available = column in header and (semantic != "stream" or stream_confirmed)
        reference["column"] = column if available else None
        reference["confirmed"] = available
    grouping["deployment_group_columns"] = ["batch_id"]
    grouping["nested_context_columns"] = [
        column for column in ("stream", "shift") if column in header
    ]
    ordering["tie_break_columns"] = ["row_sequence"] if "row_sequence" in header else []
    confirmation["confirmed_fields"] = list(CONFIRMATION_FIELD_ORDER)
    return canonicalize_audit_contract(value)


def _context(
    tmp_path: Path,
    *,
    name: str,
    rows: tuple[tuple[str, ...], ...],
    header: tuple[str, ...] = HEADER,
    stream_confirmed: bool = True,
) -> _Context:
    normalized = _csv(rows, header)
    repository = SourceRepository(RuntimeSettings(ephemeral_root=tmp_path / f"runtime-{name}"))
    run = repository.create_run()
    source = repository.register_built_in(
        run.run_id,
        built_in_key=name,
        display_name=f"Macro 01 {name}",
        payload=normalized,
    )
    profile = profile_dataset(repository, run_id=run.run_id, source_id=source.source_id)
    assert isinstance(profile, DatasetProfile)
    contract = _contract_for_profile(
        profile,
        header=header,
        stream_confirmed=stream_confirmed,
    )
    report = validate_audit_contract(contract, profile)
    assert report.valid and analysis_is_permitted(report)
    return _Context(
        repository=repository,
        run_id=run.run_id,
        source_id=source.source_id,
        normalized=normalized,
        profile=profile,
        contract=contract,
    )


def _stage1_context(tmp_path: Path) -> _Context:
    normalized = (STAGE1_ROOT / "normalized.csv").read_bytes()
    repository = SourceRepository(RuntimeSettings(ephemeral_root=tmp_path / "runtime-stage1"))
    run = repository.create_run()
    source = repository.register_built_in(
        run.run_id,
        built_in_key="stage1_fixture",
        display_name="Stage 1 public synthetic",
        payload=normalized,
    )
    profile = profile_dataset(repository, run_id=run.run_id, source_id=source.source_id)
    assert isinstance(profile, DatasetProfile)
    assert profile.to_canonical_dict() == json.loads(
        (STAGE1_ROOT / "dataset_profile.json").read_text(encoding="utf-8")
    )
    contract = AuditContract.model_validate_json(
        (STAGE1_ROOT / "confirmed_contract.json").read_text(encoding="utf-8")
    )
    return _Context(repository, run.run_id, source.source_id, normalized, profile, contract)


def _run(context: _Context, *, builder: EvidenceLedgerBuilder | None = None) -> RiecCoreResult:
    result = run_grouped_riec_core(
        context.repository,
        run_id=context.run_id,
        source_id=context.source_id,
        contract=context.contract,
        dataset_profile=context.profile,
        registry_snapshot=load_run_registry_snapshot(),
        evidence_builder=builder,
    )
    assert isinstance(result, RiecCoreResult), (
        result.to_canonical_dict() if isinstance(result, ErrorEnvelope) else result
    )
    return result


def _error(result: RiecCoreResult | ErrorEnvelope, code: str) -> ErrorEnvelope:
    assert isinstance(result, ErrorEnvelope)
    assert result.code == code
    return result


def test_safe_service_appends_one_unfinalized_evidence_item_and_validates_canonically(
    tmp_path: Path,
) -> None:
    context = _stage1_context(tmp_path)
    artifact_run_id = f"RUN-{context.run_id[4:16].upper()}"
    wrong_builder = EvidenceLedgerBuilder("RUN-FFFFFFFFFFFF")
    rejected = run_grouped_riec_core(
        context.repository,
        run_id=context.run_id,
        source_id=context.source_id,
        contract=context.contract,
        dataset_profile=context.profile,
        registry_snapshot=load_run_registry_snapshot(),
        evidence_builder=wrong_builder,
    )
    _error(rejected, "RIEC_RUN_OWNERSHIP_MISMATCH")
    assert wrong_builder.items == ()

    builder = EvidenceLedgerBuilder(artifact_run_id)
    result = _run(context, builder=builder)
    snapshot = load_run_registry_snapshot()
    contract_hash = compute_contract_hash(context.contract).canonical_contract_sha256

    assert result.source_run_id == context.run_id
    assert result.artifact_run_id == artifact_run_id == result.selection.run_id == builder.run_id
    assert len(builder.items) == len(builder.bound_items) == 1
    assert not builder.finalized
    assert builder.items[0] == result.evidence_item
    assert (
        verify_evidence_item(result.evidence_item).evidence_id == result.evidence_item.evidence_id
    )
    candidate_table = result.evidence_item.value["candidate_table"]
    assert isinstance(candidate_table, tuple) and len(candidate_table) == 7
    assert {source.artifact_id for source in result.evidence_item.source_refs} == {
        "candidate.registry",
        "normalized.dataset",
    }
    assert RiecSelection.model_validate(result.selection.to_canonical_dict()) == result.selection
    assert tuple(item.candidate_id for item in result.selection.candidate_ledger) == (
        FROZEN_CANDIDATE_IDS
    )
    baseline = next(
        item for item in result.candidate_evaluations if item.candidate_id == "M0_intercept"
    )
    assert baseline.status is EvaluationStatus.OK
    assert len(baseline.folds) == context.profile.column_profiles[2].unique_count == 8
    assert sum(fold.n_test for fold in baseline.folds) == context.profile.row_count == 80
    assert all(fold.n_train + fold.n_test == 80 for fold in baseline.folds)
    assert result.dataset_id == context.profile.dataset_id
    assert result.dataset_sha256 == context.profile.dataset_sha256
    assert result.contract_id == context.contract.contract_id
    assert result.contract_sha256 == contract_hash
    assert result.candidate_registry_id == snapshot.candidate_registry.logical_id
    assert result.candidate_registry_version == snapshot.candidate_registry.version
    assert result.candidate_registry_sha256 == snapshot.candidate_registry.canonical_json_sha256

    serialized = json.dumps(
        {
            "selection": result.selection.to_canonical_dict(),
            "evidence": result.evidence_item.to_canonical_dict(),
        },
        sort_keys=True,
    )
    assert str(tmp_path) not in serialized
    assert context.run_id not in serialized
    assert context.source_id not in serialized
    assert "product_A" not in serialized and "quantity" not in serialized
    assert re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", serialized, re.I) is None

    chained_builder = EvidenceLedgerBuilder(artifact_run_id)
    contract_parent = chained_builder.append_new(
        component=EvidenceComponent.CONTRACT,
        kind=EvidenceKind.PROVENANCE,
        status=EvidenceStatus.OK,
        statement="The confirmed audit contract is bound to the normalized dataset.",
        value={"contract_id": context.contract.contract_id},
        unit=None,
        source_refs=(),
        parent_evidence_ids=(),
        input_sha256=context.profile.dataset_sha256,
        contract_sha256=contract_hash,
        implementation_version="integration-fixture.1.0.0",
        created_at=context.contract.confirmation.confirmed_at or "2026-07-20T00:00:00Z",
    )
    chained = _run(context, builder=chained_builder)
    assert len(chained_builder.items) == 2
    assert chained.evidence_item.parent_evidence_ids == (contract_parent.item.evidence_id,)
    assert chained.evidence_item.value["provenance_mode"] == "contract_parent_bound"


def test_product_signal_selects_a_product_capable_candidate_and_keeps_all_seven(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path, name="product_signal", rows=_product_rows())
    result = _run(context)

    assert result.decision.raw_numeric_winner in set(FROZEN_CANDIDATE_IDS) - {"M0_intercept"}
    assert result.selection.raw_numeric_winner == result.decision.raw_numeric_winner
    assert len(result.selection.candidate_ledger) == len(result.candidate_evaluations) == 7
    assert all(
        item.n_rows == 80 and item.n_groups == 4 for item in result.selection.candidate_ledger
    )
    assert result.splitter == "leave_one_deployment_group_out"
    assert result.risk_aggregation == "row_weighted_grouped_mse"


def test_missing_stream_marks_only_stream_candidates_infeasible(tmp_path: Path) -> None:
    rows = _product_rows()
    stream_index = HEADER.index("stream")
    header = tuple(column for column in HEADER if column != "stream")
    without_stream = tuple(
        tuple(value for index, value in enumerate(row) if index != stream_index) for row in rows
    )
    context = _context(
        tmp_path,
        name="missing_stream",
        rows=without_stream,
        header=header,
        stream_confirmed=False,
    )
    result = _run(context)
    ledger = {item.candidate_id: item for item in result.selection.candidate_ledger}

    for candidate_id in (
        "M2_product_stream",
        "M4_product_stream_shift",
        "M6_product_stream_shift_time",
    ):
        assert ledger[candidate_id].status is CandidateStatus.INFEASIBLE
        assert ledger[candidate_id].failure_code == "CANDIDATE_REQUIRED_SEMANTIC_MISSING"
    for candidate_id in ("M0_intercept", "M1_product", "M3_product_shift", "M5_product_time"):
        assert ledger[candidate_id].status is CandidateStatus.OK


def test_baseline_failure_and_registry_tamper_fail_closed(tmp_path: Path) -> None:
    constant = _context(
        tmp_path,
        name="constant_baseline",
        rows=_product_rows(constant_quantity=True),
    )
    baseline_failure = run_grouped_riec_core(
        constant.repository,
        run_id=constant.run_id,
        source_id=constant.source_id,
        contract=constant.contract,
        dataset_profile=constant.profile,
        registry_snapshot=load_run_registry_snapshot(),
    )
    _error(baseline_failure, "RIEC_BASELINE_INELIGIBLE")

    valid = _context(tmp_path, name="tamper_source", rows=_product_rows())
    snapshot = load_run_registry_snapshot()
    false_candidate = replace(snapshot.candidate_registry, canonical_json_sha256="0" * 64)
    tampered = replace(snapshot, candidate_registry=false_candidate)
    registry_failure = run_grouped_riec_core(
        valid.repository,
        run_id=valid.run_id,
        source_id=valid.source_id,
        contract=valid.contract,
        dataset_profile=valid.profile,
        registry_snapshot=tampered,
    )
    error = _error(registry_failure, "RIEC_REGISTRY_MISMATCH")
    assert error.safe_details == {}

    false_protocol = replace(snapshot.protocol_registry, version="9.9.9")
    forged_full_snapshot = replace(snapshot, protocol_registry=false_protocol)
    full_snapshot_failure = run_grouped_riec_core(
        valid.repository,
        run_id=valid.run_id,
        source_id=valid.source_id,
        contract=valid.contract,
        dataset_profile=valid.profile,
        registry_snapshot=forged_full_snapshot,
    )
    _error(full_snapshot_failure, "RIEC_REGISTRY_MISMATCH")


def test_group_unique_stream_exposes_logo_failure_while_random_rows_look_optimistic(
    tmp_path: Path,
) -> None:
    rows = _product_rows(
        group_offsets=(0.0, 2.0, -2.0, 4.0),
        group_unique_stream=True,
    )
    context = _context(tmp_path, name="leakage_trap", rows=rows)
    result = _run(context)
    evaluations = {item.candidate_id: item for item in result.candidate_evaluations}

    assert evaluations["M0_intercept"].status is EvaluationStatus.OK
    assert evaluations["M2_product_stream"].status is EvaluationStatus.PREDICTION_FAILED
    assert evaluations["M2_product_stream"].failure_code == "CANDIDATE_UNSEEN_LEVEL"
    assert result.splitter == "leave_one_deployment_group_out"

    prepared = prepare_dataset(context.normalized, context.contract)
    candidate = load_run_registry_snapshot().candidate_registry.payload.candidates[2]
    test_indices = tuple(index for index in range(prepared.n_rows) if index % 20 % 4 < 2)
    train_indices = tuple(index for index in range(prepared.n_rows) if index not in test_indices)
    training = build_training_design(prepared, candidate, train_indices)
    test = build_prediction_design(prepared, training.specification, test_indices)
    fit = fit_ols(training.values, training.response, n_eff=len(train_indices))
    predictions = predict_ols(fit, test.values)
    random_row_mse = math.fsum(
        (observed - predicted) ** 2
        for observed, predicted in zip(test.response, predictions, strict=True)
    ) / len(test.response)
    baseline_risk = evaluations["M0_intercept"].grouped_risk
    assert baseline_risk is not None and random_row_mse < baseline_risk


def test_row_permutation_group_renaming_and_repeat_preserve_numerical_results(
    tmp_path: Path,
) -> None:
    rows = _product_rows()
    permuted_rows = tuple(rows[index] for index in tuple(range(79, -1, -1)))
    renamed_rows = _product_rows(group_labels=("renamed-z", "renamed-a", "renamed-m", "renamed-b"))
    original = _run(_context(tmp_path, name="invariant_original", rows=rows))
    repeated = _run(_context(tmp_path, name="invariant_repeat_source", rows=rows))
    permuted = _run(_context(tmp_path, name="invariant_permuted", rows=permuted_rows))
    renamed = _run(_context(tmp_path, name="invariant_renamed", rows=renamed_rows))

    def assert_same_numbers(left: RiecCoreResult, right: RiecCoreResult) -> None:
        assert left.decision.raw_numeric_winner == right.decision.raw_numeric_winner
        assert left.decision.runner_up == right.decision.runner_up
        assert left.decision.equivalence_set == right.decision.equivalence_set
        assert left.decision.score_gap == pytest.approx(right.decision.score_gap, abs=1e-10)
        for left_item, right_item in zip(
            left.candidate_evaluations,
            right.candidate_evaluations,
            strict=True,
        ):
            assert left_item.candidate_id == right_item.candidate_id
            assert left_item.status is right_item.status
            if left_item.grouped_risk is None or right_item.grouped_risk is None:
                assert left_item.grouped_risk is right_item.grouped_risk is None
            else:
                assert left_item.grouped_risk == pytest.approx(
                    right_item.grouped_risk,
                    abs=1e-12,
                )
            if left_item.group_balanced_risk is None or right_item.group_balanced_risk is None:
                assert left_item.group_balanced_risk is right_item.group_balanced_risk is None
            else:
                assert left_item.group_balanced_risk == pytest.approx(
                    right_item.group_balanced_risk,
                    abs=1e-12,
                )
            if left_item.full_fit is not None and right_item.full_fit is not None:
                assert left_item.full_fit.bic_eff == pytest.approx(
                    right_item.full_fit.bic_eff,
                    abs=1e-10,
                )

    assert_same_numbers(original, repeated)
    assert_same_numbers(original, permuted)
    assert_same_numbers(original, renamed)


def test_primary_risk_is_pooled_by_rows_and_balanced_risk_is_diagnostic(tmp_path: Path) -> None:
    rows = _product_rows(
        group_sizes=(8, 12, 20, 40),
        group_offsets=(0.0, 1.0, -2.0, 5.0),
    )
    result = _run(_context(tmp_path, name="unequal_groups", rows=rows))
    baseline = next(
        item for item in result.candidate_evaluations if item.candidate_id == "M0_intercept"
    )
    assert baseline.status is EvaluationStatus.OK
    assert all(fold.sse is not None and fold.mse is not None for fold in baseline.folds)
    pooled = math.fsum(fold.sse or 0.0 for fold in baseline.folds) / 80
    balanced = math.fsum(fold.mse or 0.0 for fold in baseline.folds) / len(baseline.folds)

    assert baseline.grouped_risk == pytest.approx(pooled)
    assert baseline.group_balanced_risk == pytest.approx(balanced)
    assert abs(pooled - balanced) > 1e-6
