from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from riec_guard.domain.normalize import UploadLimits
from riec_guard.domain.source import SourceKind, SourceRepository, SourceSpec
from riec_guard.errors import ApplicationError, ErrorCode
from riec_guard.settings import RuntimeSettings

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
VALID_CSV = b"quantity,batch\n10.1,A\n10.2,B\n"


def _repository(tmp_path: Path, *, limits: UploadLimits | None = None) -> SourceRepository:
    return SourceRepository(
        RuntimeSettings(ephemeral_root=tmp_path / "ephemeral-runs"),
        limits=limits,
    )


def test_built_in_and_upload_share_source_spec_abstraction(tmp_path: Path):
    repository = _repository(tmp_path)
    run = repository.create_run()
    built_in = repository.register_built_in(
        run.run_id,
        built_in_key="stable_symmetric",
        display_name="Stable symmetric",
    )
    uploaded = repository.register_upload(
        run.run_id,
        display_name="measurements.csv",
        media_type="text/csv",
        payload=VALID_CSV,
    )

    assert isinstance(built_in, SourceSpec)
    assert isinstance(uploaded, SourceSpec)
    assert built_in.kind is SourceKind.BUILT_IN
    assert uploaded.kind is SourceKind.UPLOADED_CSV
    assert built_in.run_id == uploaded.run_id == run.run_id


def test_valid_csv_is_copied_and_normalized_with_generated_storage_name(tmp_path: Path):
    repository = _repository(tmp_path)
    run = repository.create_run()
    source = repository.register_upload(
        run.run_id,
        display_name="customer measurements.csv",
        media_type="text/csv",
        payload=VALID_CSV,
    )

    input_path = repository.input_path(run.run_id, source.source_id)
    normalized_path = repository.normalized_path(run.run_id, source.source_id)
    assert input_path == run.inputs / f"{source.source_id}.csv"
    assert normalized_path == run.normalized / f"{source.source_id}.csv"
    assert input_path.read_bytes() == VALID_CSV
    assert normalized_path.read_bytes() == VALID_CSV
    assert input_path.stat().st_mode & 0o777 == 0o600
    assert source.display_name == "customer measurements.csv"
    assert "customer" not in input_path.name
    assert "measurements" not in input_path.name


def test_source_metadata_is_deterministically_json_serializable(tmp_path: Path):
    repository = _repository(tmp_path)
    run = repository.create_run()
    source = repository.register_upload(
        run.run_id,
        display_name="measurements.csv",
        media_type="application/csv",
        payload=VALID_CSV,
    )
    encoded = json.dumps(source.to_metadata(), sort_keys=True)
    assert source.source_id in encoded
    assert '"kind": "uploaded_csv"' in encoded
    assert '"data_row_count": 2' in encoded
    assert '"column_count": 2' in encoded


def test_upload_and_normalized_files_are_outside_git_repository(tmp_path: Path):
    repository = _repository(tmp_path)
    run = repository.create_run()
    source = repository.register_upload(
        run.run_id,
        display_name="measurements.csv",
        media_type="text/csv",
        payload=VALID_CSV,
    )
    for path in (
        repository.input_path(run.run_id, source.source_id),
        repository.normalized_path(run.run_id, source.source_id),
    ):
        assert not path.resolve().is_relative_to(REPOSITORY_ROOT.resolve())
        assert path.resolve().is_relative_to(run.run_root.resolve())


def test_built_in_source_requires_no_copied_file(tmp_path: Path):
    repository = _repository(tmp_path)
    run = repository.create_run()
    source = repository.register_built_in(
        run.run_id,
        built_in_key="left_skew_foaming",
        display_name="Left skew / foaming",
    )
    assert source.built_in_key == "left_skew_foaming"
    assert list(run.inputs.iterdir()) == []
    assert list(run.normalized.iterdir()) == []


def test_source_from_one_run_cannot_resolve_through_another(tmp_path: Path):
    repository = _repository(tmp_path)
    owner = repository.create_run()
    other = repository.create_run()
    source = repository.register_upload(
        owner.run_id,
        display_name="measurements.csv",
        media_type="text/csv",
        payload=VALID_CSV,
    )
    with pytest.raises(ApplicationError) as exc_info:
        repository.get_source(other.run_id, source.source_id)
    assert exc_info.value.code is ErrorCode.SOURCE_NOT_FOUND
    assert repository.get_source(owner.run_id, source.source_id) == source


def test_missing_source_and_run_have_stable_safe_errors(tmp_path: Path):
    repository = _repository(tmp_path)
    run = repository.create_run()
    with pytest.raises(ApplicationError) as source_error:
        repository.get_source(run.run_id, "SRC-00000000000000000000000000000000")
    assert source_error.value.code is ErrorCode.SOURCE_NOT_FOUND
    assert "/" not in str(source_error.value)

    with pytest.raises(ApplicationError) as run_error:
        repository.get_source("RUN-00000000000000000000000000000000", "not-a-source")
    assert run_error.value.code is ErrorCode.RUN_NOT_FOUND
    assert "/" not in str(run_error.value)


def test_cleanup_existing_run_succeeds_and_repeat_is_idempotent(tmp_path: Path):
    repository = _repository(tmp_path)
    run = repository.create_run()
    repository.register_upload(
        run.run_id,
        display_name="measurements.csv",
        media_type="text/csv",
        payload=VALID_CSV,
    )
    assert repository.delete_run(run.run_id) is True
    assert not run.run_root.exists()
    assert repository.delete_run(run.run_id) is False


def test_expired_cleanup_leaves_active_and_nonexpired_runs(tmp_path: Path):
    repository = _repository(tmp_path)
    expired = repository.create_run()
    active = repository.create_run()
    recent = repository.create_run()
    now = datetime(2026, 7, 19, tzinfo=timezone.utc)
    old_timestamp = (now - timedelta(days=2)).timestamp()
    recent_timestamp = (now - timedelta(minutes=5)).timestamp()
    os.utime(expired.run_root, (old_timestamp, old_timestamp))
    os.utime(active.run_root, (old_timestamp, old_timestamp))
    os.utime(recent.run_root, (recent_timestamp, recent_timestamp))

    removed = repository.cleanup_expired(
        older_than=now - timedelta(hours=1),
        active_run_ids={active.run_id},
    )
    assert removed == (expired.run_id,)
    assert not expired.run_root.exists()
    assert active.run_root.is_dir()
    assert recent.run_root.is_dir()


def test_symlink_run_cleanup_unlinks_only_redirect_and_preserves_outside(tmp_path: Path):
    repository = _repository(tmp_path)
    run = repository.create_run()
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("preserve", encoding="utf-8")
    shutil.rmtree(run.run_root)
    run.run_root.symlink_to(outside, target_is_directory=True)

    assert repository.delete_run(run.run_id) is True
    assert not run.run_root.exists()
    assert sentinel.read_text(encoding="utf-8") == "preserve"


def test_cleanup_cannot_delete_ephemeral_root_itself(tmp_path: Path):
    repository = _repository(tmp_path)
    run = repository.create_run()
    ephemeral_root = run.run_root.parent
    with pytest.raises(ApplicationError) as exc_info:
        repository.delete_run(ephemeral_root.name)
    assert exc_info.value.code is ErrorCode.RUN_NOT_FOUND
    assert ephemeral_root.is_dir()
    assert run.run_root.is_dir()


def test_redirected_ephemeral_root_causes_safe_cleanup_failure(tmp_path: Path):
    repository = _repository(tmp_path)
    run = repository.create_run()
    ephemeral_root = run.run_root.parent
    parked_root = tmp_path / "parked-root"
    ephemeral_root.rename(parked_root)
    outside = tmp_path / "outside-root"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("preserve", encoding="utf-8")
    ephemeral_root.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ApplicationError) as exc_info:
        repository.delete_run(run.run_id)
    assert exc_info.value.code is ErrorCode.CLEANUP_FAILURE
    assert sentinel.read_text(encoding="utf-8") == "preserve"
