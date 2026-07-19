from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from riec_guard.contract.models import ColumnDataType, DatasetProfile, SemanticRole
from riec_guard.contract.profiler import (
    ProfilerConfig,
    ProfilingHints,
    SemanticHint,
    _scan_normalized_csv,
    profile_dataset,
)
from riec_guard.domain.source import SourceRepository
from riec_guard.errors import ErrorClass, ErrorEnvelope, ErrorStage
from riec_guard.settings import RuntimeSettings


def _repository(tmp_path: Path) -> SourceRepository:
    return SourceRepository(RuntimeSettings(ephemeral_root=tmp_path / "ephemeral-runs"))


def _upload(
    tmp_path: Path,
    payload: bytes,
    *,
    display_name: str = "public-measurements.csv",
) -> tuple[SourceRepository, str, str]:
    repository = _repository(tmp_path)
    run = repository.create_run()
    source = repository.register_upload(
        run.run_id,
        display_name=display_name,
        media_type="text/csv",
        payload=payload,
    )
    return repository, run.run_id, source.source_id


def _profile(
    tmp_path: Path,
    payload: bytes,
    *,
    hints: ProfilingHints | None = None,
    config: ProfilerConfig | None = None,
) -> DatasetProfile | ErrorEnvelope:
    repository, run_id, source_id = _upload(tmp_path, payload)
    return profile_dataset(
        repository,
        run_id=run_id,
        source_id=source_id,
        hints=hints,
        config=config,
    )


def _assert_error(result: DatasetProfile | ErrorEnvelope, code: str) -> ErrorEnvelope:
    assert isinstance(result, ErrorEnvelope)
    assert result.stage is ErrorStage.PROFILE
    assert result.error_class in {ErrorClass.VALIDATION, ErrorClass.DATA_QUALITY}
    assert result.code == code
    result.to_canonical_dict()
    return result


def test_built_in_and_upload_use_the_same_profiler_entry_point(tmp_path: Path) -> None:
    payload = b"quantity,batch_id\n10,A\n11,B\n"
    repository = _repository(tmp_path)
    run = repository.create_run()
    uploaded = repository.register_upload(
        run.run_id,
        display_name="measurements.csv",
        media_type="text/csv",
        payload=payload,
    )
    built_in = repository.register_built_in(
        run.run_id,
        built_in_key="stable_symmetric",
        display_name="Stable symmetric",
        payload=payload,
    )

    uploaded_profile = profile_dataset(repository, run_id=run.run_id, source_id=uploaded.source_id)
    built_in_profile = profile_dataset(repository, run_id=run.run_id, source_id=built_in.source_id)

    assert isinstance(uploaded_profile, DatasetProfile)
    assert built_in_profile == uploaded_profile
    assert list(run.inputs.iterdir()) == [run.inputs / f"{uploaded.source_id}.csv"]


def test_valid_profile_is_canonical_schema_valid_and_hashes_exact_normalized_bytes(
    tmp_path: Path,
) -> None:
    repository, run_id, source_id = _upload(tmp_path, b"quantity,batch_id\r\n10,A\r\n11,B\r\n")
    result = profile_dataset(repository, run_id=run_id, source_id=source_id)

    assert isinstance(result, DatasetProfile)
    normalized = repository.read_normalized_bytes(run_id, source_id)
    expected_hash = hashlib.sha256(normalized).hexdigest()
    assert result.dataset_sha256 == expected_hash
    assert result.dataset_id == f"dataset-{expected_hash[:16]}"
    assert re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,127}", result.dataset_id)
    assert result.to_canonical_dict()["schema_version"] == "1.0.0"


def test_identical_normalized_data_is_byte_deterministic_across_runs(tmp_path: Path) -> None:
    payload = b"quantity,batch_id\r\n1,A\r\n2,B\r\n"
    first_repository, first_run, first_source = _upload(tmp_path / "one", payload)
    second_repository, second_run, second_source = _upload(tmp_path / "two", payload)

    first = profile_dataset(first_repository, run_id=first_run, source_id=first_source)
    second = profile_dataset(second_repository, run_id=second_run, source_id=second_source)

    assert isinstance(first, DatasetProfile)
    assert isinstance(second, DatasetProfile)
    assert first.to_canonical_json() == second.to_canonical_json()


def test_different_normalized_data_changes_identity(tmp_path: Path) -> None:
    first = _profile(tmp_path / "one", b"quantity\n1\n")
    second = _profile(tmp_path / "two", b"quantity\n2\n")
    assert isinstance(first, DatasetProfile)
    assert isinstance(second, DatasetProfile)
    assert first.dataset_sha256 != second.dataset_sha256
    assert first.dataset_id != second.dataset_id


def test_column_order_row_count_missing_and_unique_policy(tmp_path: Path) -> None:
    result = _profile(
        tmp_path,
        b"batch_id,quantity,product\nA,1,NA\nA,,NA\nB,3,X\n",
    )
    assert isinstance(result, DatasetProfile)
    assert result.row_count == 3
    assert tuple(column.name for column in result.column_profiles) == (
        "batch_id",
        "quantity",
        "product",
    )
    quantity = result.column_profiles[1]
    product = result.column_profiles[2]
    assert quantity.missing_fraction == pytest.approx(1 / 3)
    assert quantity.unique_count == 2
    assert product.missing_fraction == 0
    assert product.unique_count == 2


def test_dtype_precedence_and_internal_finite_diagnostics(tmp_path: Path) -> None:
    payload = (
        b"quantity,count,ratio,enabled,production_datetime,code\n"
        b"1,001,1.5,true,2026-07-18T01:02:03Z,2026-01-01\n"
        b"2,002,2e1,false,2026-07-19T01:02:03Z,2026-01-02\n"
    )
    result = _profile(tmp_path, payload)
    assert isinstance(result, DatasetProfile)
    assert tuple(column.dtype for column in result.column_profiles) == (
        ColumnDataType.INTEGER,
        ColumnDataType.INTEGER,
        ColumnDataType.NUMBER,
        ColumnDataType.BOOLEAN,
        ColumnDataType.DATETIME,
        ColumnDataType.STRING,
    )

    scan = _scan_normalized_csv(payload, ProfilerConfig())
    assert scan.columns[2].finite_numeric_count == 2
    assert scan.columns[2].numeric_parse_failure_count == 0
    assert scan.columns[4].datetime_parse_count == 2


def test_mixed_ambiguous_column_remains_string(tmp_path: Path) -> None:
    result = _profile(tmp_path, b"quantity,mixed\n1,10\n2,word\n")
    assert isinstance(result, DatasetProfile)
    assert result.column_profiles[1].dtype is ColumnDataType.STRING
    assert result.column_profiles[1].numeric_summary is None


def test_numeric_summary_and_even_median_are_deterministic(tmp_path: Path) -> None:
    result = _profile(tmp_path, b"quantity\n1\n2\n100\n101\n")
    assert isinstance(result, DatasetProfile)
    summary = result.column_profiles[0].numeric_summary
    assert summary is not None
    assert (summary.min, summary.median, summary.max) == (1, 51.0, 101)
    assert result.column_profiles[0].safe_examples == (1, 51.0, 101)


def test_semantic_candidates_are_complete_multiple_and_stably_ordered(tmp_path: Path) -> None:
    result = _profile(
        tmp_path,
        (
            b"weight,quantity,sku,batch_id,production_datetime,nozzle,shift\n"
            b"10,9,P1,B1,2026-07-18T01:00:00Z,N1,day\n"
            b"11,10,P1,B2,2026-07-18T02:00:00Z,N2,night\n"
        ),
    )
    assert isinstance(result, DatasetProfile)
    mappings = result.candidate_semantic_mappings
    quantities = [
        mapping.column for mapping in mappings if mapping.semantic_role is SemanticRole.QUANTITY
    ]
    assert quantities == ["weight", "quantity"]
    assert {
        SemanticRole.PRODUCT,
        SemanticRole.DEPLOYMENT_GROUP,
        SemanticRole.TIME,
        SemanticRole.STREAM,
        SemanticRole.SHIFT,
        SemanticRole.WEIGHT,
    }.issubset({mapping.semantic_role for mapping in mappings})
    role_order = [
        SemanticRole.QUANTITY,
        SemanticRole.PRODUCT,
        SemanticRole.DEPLOYMENT_GROUP,
        SemanticRole.TIME,
        SemanticRole.STREAM,
        SemanticRole.SHIFT,
        SemanticRole.WEIGHT,
        SemanticRole.DENSITY,
        SemanticRole.TARE,
    ]
    positions = {role: index for index, role in enumerate(role_order)}
    assert [positions[mapping.semantic_role] for mapping in mappings] == sorted(
        positions[mapping.semantic_role] for mapping in mappings
    )
    assert all(reason.startswith("inferred:") for mapping in mappings for reason in mapping.reasons)


def test_supplied_semantic_hint_is_labelled_and_never_confirmed(tmp_path: Path) -> None:
    result = _profile(
        tmp_path,
        b"amount,batch\n1,A\n2,B\n",
        hints=ProfilingHints(semantic_hints=(SemanticHint(SemanticRole.QUANTITY, "amount"),)),
    )
    assert isinstance(result, DatasetProfile)
    mapping = result.candidate_semantic_mappings[0]
    assert mapping.semantic_role is SemanticRole.QUANTITY
    assert mapping.column == "amount"
    assert mapping.reasons == (
        "supplied: caller-provided semantic hint; suggestion only, not confirmed",
    )


def test_quantity_only_profile_does_not_manufacture_group_or_order(tmp_path: Path) -> None:
    result = _profile(tmp_path, b"quantity\n1\n2\n")
    assert isinstance(result, DatasetProfile)
    assert tuple(mapping.semantic_role for mapping in result.candidate_semantic_mappings) == (
        SemanticRole.QUANTITY,
    )


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        (b"quantity\n", "PROFILE_EMPTY_DATASET"),
        (b"quantity,Quantity\n1,2\n", "PROFILE_DUPLICATE_COLUMN_NAME"),
        (b"quantity,bad/name\n1,A\n", "PROFILE_INVALID_COLUMN_NAME"),
        (b"product\nA\n", "PROFILE_MISSING_QUANTITY"),
        (b"quantity\n1\nnot-a-number\n", "PROFILE_MALFORMED_NUMERIC"),
        (b"quantity\n1\nNaN\n", "PROFILE_NONFINITE_VALUE"),
        (b"quantity\n1e999\n", "PROFILE_NONFINITE_VALUE"),
        (b"row_id,quantity\nR1,1\nR1,2\n", "PROFILE_DUPLICATE_ROW_ID"),
    ],
)
def test_structured_profile_failures(tmp_path: Path, payload: bytes, code: str) -> None:
    _assert_error(_profile(tmp_path, payload), code)


def test_explicit_row_id_hint_detects_duplicates_without_echoing_value(tmp_path: Path) -> None:
    result = _profile(
        tmp_path,
        b"custom_key,quantity\nSECRET-DUPLICATE,1\nSECRET-DUPLICATE,2\n",
        hints=ProfilingHints(row_id_column="custom_key"),
    )
    error = _assert_error(result, "PROFILE_DUPLICATE_ROW_ID")
    assert "SECRET-DUPLICATE" not in error.to_canonical_json()


def test_repeated_process_ids_do_not_trigger_row_identity_failure(tmp_path: Path) -> None:
    result = _profile(
        tmp_path,
        (b"batch_id,product_id,stream_id,shift_id,quantity\nB1,P1,S1,D,1\nB1,P1,S1,D,2\n"),
    )
    assert isinstance(result, DatasetProfile)


def test_invalid_materialized_normalized_csv_returns_structured_error(tmp_path: Path) -> None:
    repository, run_id, source_id = _upload(tmp_path, b"quantity\n1\n")
    repository.normalized_path(run_id, source_id).write_bytes(b'quantity\n"unterminated\n')
    result = profile_dataset(repository, run_id=run_id, source_id=source_id)
    _assert_error(result, "PROFILE_INVALID_NORMALIZED_CSV")


def test_profiler_limit_violation_is_structured(tmp_path: Path) -> None:
    result = _profile(
        tmp_path,
        b"quantity\n1\n2\n",
        config=ProfilerConfig(max_rows=1),
    )
    _assert_error(result, "PROFILE_LIMIT_EXCEEDED")


def test_cross_run_and_missing_source_are_safe_profile_errors(tmp_path: Path) -> None:
    repository, owner_run, source_id = _upload(tmp_path, b"quantity\n1\n")
    other_run = repository.create_run()

    cross_run = profile_dataset(repository, run_id=other_run.run_id, source_id=source_id)
    missing = profile_dataset(
        repository,
        run_id=owner_run,
        source_id="SRC-00000000000000000000000000000000",
    )

    _assert_error(cross_run, "PROFILE_SOURCE_NOT_FOUND")
    _assert_error(missing, "PROFILE_SOURCE_NOT_FOUND")


def test_unmaterialized_built_in_returns_source_not_found(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    run = repository.create_run()
    source = repository.register_built_in(
        run.run_id,
        built_in_key="left_skew_foaming",
        display_name="Left skew / foaming",
    )
    result = profile_dataset(repository, run_id=run.run_id, source_id=source.source_id)
    _assert_error(result, "PROFILE_SOURCE_NOT_FOUND")
