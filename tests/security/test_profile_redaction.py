from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from riec_guard.contract.models import DatasetProfile
from riec_guard.contract.profiler import ProfilerConfig, profile_dataset
from riec_guard.contract.schema_loader import load_schema_registry
from riec_guard.domain.source import SourceRepository
from riec_guard.errors import ErrorEnvelope
from riec_guard.settings import RuntimeSettings


def _profile(
    tmp_path: Path,
    payload: bytes,
    *,
    display_name: str = "operator-private-export.csv",
    config: ProfilerConfig | None = None,
) -> tuple[DatasetProfile | ErrorEnvelope, SourceRepository, str, str]:
    repository = SourceRepository(RuntimeSettings(ephemeral_root=tmp_path / "ephemeral-runs"))
    run = repository.create_run()
    source = repository.register_upload(
        run.run_id,
        display_name=display_name,
        media_type="text/csv",
        payload=payload,
    )
    result = profile_dataset(
        repository,
        run_id=run.run_id,
        source_id=source.source_id,
        config=config,
    )
    return result, repository, run.run_id, source.source_id


def _synthetic_email_address(local_part: str) -> str:
    return "".join((local_part, chr(64), "example", chr(46), "invalid"))


def _synthetic_phone_contact(suffix: str) -> str:
    return "".join(("+", "1", " (", "202", ") ", "555", "-", suffix))


def _assert_sensitive_markers_absent(serialized: str, markers: tuple[str, ...]) -> None:
    if any(marker in serialized for marker in markers):
        pytest.fail("a synthetic direct-identifier marker reached public output")


def test_serialized_profile_has_no_rows_paths_run_roots_or_original_filename(
    tmp_path: Path,
) -> None:
    payload = b"quantity,batch_id\n12345.25,BATCH-SECRET-A\n54321.75,BATCH-SECRET-B\n"
    result, repository, run_id, source_id = _profile(tmp_path, payload)
    assert isinstance(result, DatasetProfile)
    serialized = result.to_canonical_json()
    normalized_path = repository.normalized_path(run_id, source_id)

    assert "operator-private-export.csv" not in serialized
    assert str(tmp_path) not in serialized
    assert str(normalized_path) not in serialized
    assert run_id not in serialized
    assert source_id not in serialized
    assert "BATCH-SECRET-A" not in serialized
    assert "BATCH-SECRET-B" not in serialized
    assert "PRIVATE_LOCAL_REFERENCE" not in serialized
    assert "ORIGINAL_PHASE_PACKAGES" not in serialized
    assert "FROZEN_REFERENCE_SPECS" not in serialized
    assert '"raw_rows":' not in serialized


def test_r01_gate_g1_neutral_label_email_shape_emits_no_safe_examples(
    tmp_path: Path,
) -> None:
    markers = (
        _synthetic_email_address("g1-alpha"),
        _synthetic_email_address("g1-beta"),
    )
    rows = [f"{index + 1},B{index % 4 + 1},{markers[index % len(markers)]}" for index in range(10)]
    payload = ("quantity,batch_id,label\n" + "\n".join(rows) + "\n").encode()

    first, _, _, _ = _profile(tmp_path / "first", payload)
    second, _, _, _ = _profile(tmp_path / "second", payload)

    assert isinstance(first, DatasetProfile)
    assert isinstance(second, DatasetProfile)
    label = first.column_profiles[2]
    assert label.unique_count == 2
    assert label.safe_examples == ()
    assert label.numeric_summary is None
    assert first.to_canonical_json() == second.to_canonical_json()
    assert not first.privacy_redaction.raw_rows_included
    assert not first.privacy_redaction.direct_identifiers_included
    assert not first.privacy_redaction.high_cardinality_values_included

    serialized = first.to_canonical_json()
    _assert_sensitive_markers_absent(serialized, markers)
    assert DatasetProfile.model_validate_json(serialized) == first
    schema = load_schema_registry().lookup("dataset_profile").validation_schema()
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(first.to_canonical_dict())


def test_r01_neutral_label_phone_shape_emits_no_safe_examples(tmp_path: Path) -> None:
    markers = (
        _synthetic_phone_contact("0101"),
        _synthetic_phone_contact("0102"),
    )
    rows = [f"{index + 1},{markers[index % len(markers)]}" for index in range(10)]
    payload = ("quantity,label\n" + "\n".join(rows) + "\n").encode()

    result, _, _, _ = _profile(tmp_path, payload)

    assert isinstance(result, DatasetProfile)
    label = result.column_profiles[1]
    assert label.unique_count == 2
    assert label.safe_examples == ()
    assert label.numeric_summary is None
    _assert_sensitive_markers_absent(result.to_canonical_json(), markers)


def test_r01_full_value_scan_redacts_mixed_column_beyond_example_candidates(
    tmp_path: Path,
) -> None:
    marker = _synthetic_email_address("zz-outside-candidates")
    labels = [("control", "hold", "treatment")[index % 3] for index in range(20)]
    labels[16] = marker
    rows = [f"{index + 1},{label}" for index, label in enumerate(labels)]
    payload = ("quantity,label\n" + "\n".join(rows) + "\n").encode()

    result, _, _, _ = _profile(tmp_path, payload)

    assert isinstance(result, DatasetProfile)
    label = result.column_profiles[1]
    assert label.unique_count == 4
    assert label.safe_examples == ()
    _assert_sensitive_markers_absent(result.to_canonical_json(), (marker,))


def test_direct_identifier_columns_never_expose_examples_or_numeric_summaries(
    tmp_path: Path,
) -> None:
    rows = [
        f"group-{index % 2 + 1},contact-{index % 2 + 1},{1001 + index % 2},{index + 1}"
        for index in range(10)
    ]
    payload = ("operator_name,email,account_id,quantity\n" + "\n".join(rows) + "\n").encode()
    result, _, _, _ = _profile(tmp_path, payload)
    assert isinstance(result, DatasetProfile)
    by_name = {column.name: column for column in result.column_profiles}

    for name in ("operator_name", "email", "account_id"):
        assert by_name[name].safe_examples == ()
        assert by_name[name].numeric_summary is None


def test_high_cardinality_string_examples_are_redacted_deterministically(tmp_path: Path) -> None:
    rows = [f"{index},VALUE-{index:02d}" for index in range(1, 23)]
    payload = ("quantity,label\n" + "\n".join(rows) + "\n").encode()
    first, _, _, _ = _profile(tmp_path / "one", payload)
    second, _, _, _ = _profile(tmp_path / "two", payload)

    assert isinstance(first, DatasetProfile)
    assert isinstance(second, DatasetProfile)
    label = first.column_profiles[1]
    assert label.unique_count == 22
    assert label.safe_examples == ()
    assert first.to_canonical_json() == second.to_canonical_json()
    assert "VALUE-01" not in first.to_canonical_json()


def test_unique_fraction_threshold_is_configurable_and_deterministic(tmp_path: Path) -> None:
    payload = b"quantity,label\n1,A\n2,B\n3,A\n4,B\n"
    default, _, _, _ = _profile(tmp_path / "default", payload)
    relaxed, _, _, _ = _profile(
        tmp_path / "relaxed",
        payload,
        config=ProfilerConfig(
            high_cardinality_unique_count=20,
            high_cardinality_unique_fraction=0.75,
        ),
    )

    assert isinstance(default, DatasetProfile)
    assert isinstance(relaxed, DatasetProfile)
    assert default.column_profiles[1].safe_examples == ()
    assert relaxed.column_profiles[1].safe_examples == ("A", "B")


def test_datetime_examples_are_always_omitted(tmp_path: Path) -> None:
    result, _, _, _ = _profile(
        tmp_path,
        (b"quantity,production_datetime\n1,2026-07-18T01:02:03Z\n2,2026-07-19T01:02:03Z\n"),
    )
    assert isinstance(result, DatasetProfile)
    assert result.column_profiles[1].safe_examples == ()
    assert "2026-07-18" not in result.to_canonical_json()


def test_low_cardinality_public_values_are_sorted_capped_and_safe(tmp_path: Path) -> None:
    rows = [
        f"{index},{('C', 'A', 'B')[index % 3]},{('treatment', 'control')[index % 2]},"
        f"{str(index % 2 == 0).lower()}"
        for index in range(1, 31)
    ]
    payload = ("quantity,shift,condition,enabled\n" + "\n".join(rows) + "\n").encode()
    result, _, _, _ = _profile(tmp_path, payload)

    assert isinstance(result, DatasetProfile)
    assert result.column_profiles[1].safe_examples == ("A", "B", "C")
    assert result.column_profiles[2].safe_examples == ("control", "treatment")
    assert result.column_profiles[3].safe_examples == (False, True)
    assert len(result.column_profiles[1].safe_examples) <= 3


@pytest.mark.parametrize("shape_category", ("email", "phone"))
def test_r01_identifier_shapes_do_not_echo_in_public_profile_errors(
    tmp_path: Path,
    shape_category: str,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    marker = (
        _synthetic_email_address("malformed-quantity")
        if shape_category == "email"
        else _synthetic_phone_contact("0199")
    )
    result, _, _, _ = _profile(
        tmp_path,
        f"quantity,label\n1,control\n{marker},treatment\n".encode(),
    )

    assert isinstance(result, ErrorEnvelope)
    assert result.code == "PROFILE_MALFORMED_NUMERIC"
    captured = capsys.readouterr()
    public_output = "\n".join((result.to_canonical_json(), captured.out, captured.err, caplog.text))
    _assert_sensitive_markers_absent(public_output, (marker,))


def test_numeric_examples_are_aggregate_derived_not_row_samples(tmp_path: Path) -> None:
    result, _, _, _ = _profile(tmp_path, b"quantity\n1\n2\n100\n101\n")
    assert isinstance(result, DatasetProfile)
    assert result.column_profiles[0].safe_examples == (1, 51.0, 101)
    assert 2 not in result.column_profiles[0].safe_examples
    assert 100 not in result.column_profiles[0].safe_examples


def test_malformed_numeric_error_does_not_echo_cell_filename_path_or_trace(
    tmp_path: Path,
) -> None:
    secret = "SENSITIVE-MALFORMED-TOKEN-123456"
    result, _, run_id, source_id = _profile(
        tmp_path,
        f"quantity\n1\n{secret}\n".encode(),
    )
    assert isinstance(result, ErrorEnvelope)
    serialized = result.to_canonical_json()
    assert result.code == "PROFILE_MALFORMED_NUMERIC"
    assert secret not in serialized
    assert "operator-private-export.csv" not in serialized
    assert str(tmp_path) not in serialized
    assert run_id not in serialized
    assert source_id not in serialized
    assert "Traceback" not in serialized
    assert "exception" not in serialized.casefold()


def test_duplicate_row_error_does_not_echo_duplicate_identifier(tmp_path: Path) -> None:
    duplicate = "PERSONAL-ROW-SECRET"
    result, _, _, _ = _profile(
        tmp_path,
        f"row_id,quantity\n{duplicate},1\n{duplicate},2\n".encode(),
    )
    assert isinstance(result, ErrorEnvelope)
    assert result.code == "PROFILE_DUPLICATE_ROW_ID"
    assert duplicate not in result.to_canonical_json()


def test_privacy_flags_are_always_false_and_canonical_json_has_no_extra_fields(
    tmp_path: Path,
) -> None:
    result, _, _, _ = _profile(tmp_path, b"quantity\n1\n2\n")
    assert isinstance(result, DatasetProfile)
    profile = json.loads(result.to_canonical_json())
    assert profile["privacy_redaction"] == {
        "direct_identifiers_included": False,
        "high_cardinality_values_included": False,
        "raw_rows_included": False,
    }
    assert set(profile) == {
        "schema_version",
        "dataset_id",
        "dataset_sha256",
        "row_count",
        "column_profiles",
        "candidate_semantic_mappings",
        "privacy_redaction",
    }


def test_unrelated_private_looking_file_is_never_discovered(tmp_path: Path) -> None:
    private_directory = tmp_path / "PRIVATE_LOCAL_REFERENCE"
    private_directory.mkdir()
    sentinel = "PRIVATE-SENTINEL-NEVER-READ"
    (private_directory / "industrial.csv").write_text(
        f"quantity,operator\n999,{sentinel}\n", encoding="utf-8"
    )

    result, _, _, _ = _profile(tmp_path, b"quantity\n1\n2\n")

    assert isinstance(result, DatasetProfile)
    assert sentinel not in result.to_canonical_json()
    assert "PRIVATE_LOCAL_REFERENCE" not in result.to_canonical_json()
