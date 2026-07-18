from __future__ import annotations

from pathlib import Path

import pytest

from riec_guard.domain.source import UploadedSource
from riec_guard.settings import RuntimeSettings, SettingsValidationError

ROOT = Path(__file__).resolve().parents[2]


def test_public_defaults_require_no_private_path():
    settings = RuntimeSettings.from_env({})
    assert settings.public_mode is True
    assert settings.private_data_root is None
    assert settings.ephemeral_root.is_absolute()
    assert not settings.ephemeral_root.is_relative_to(ROOT)


def test_hosted_mode_refuses_private_mode(tmp_path: Path):
    with pytest.raises(SettingsValidationError, match="hosted_mode"):
        RuntimeSettings(
            mode="private",
            hosted_mode=True,
            ephemeral_root=tmp_path / "public",
            private_data_root=tmp_path / "private-data",
        )


def test_identical_roots_are_rejected(tmp_path: Path):
    with pytest.raises(SettingsValidationError, match="different roots"):
        RuntimeSettings.private_local(
            ephemeral_root=tmp_path / "same",
            private_data_root=tmp_path / "same",
        )


def test_public_nested_inside_private_is_rejected(tmp_path: Path):
    with pytest.raises(SettingsValidationError, match="different roots"):
        RuntimeSettings.private_local(
            ephemeral_root=tmp_path / "private-data" / "public",
            private_data_root=tmp_path / "private-data",
        )


def test_private_nested_inside_public_is_rejected(tmp_path: Path):
    with pytest.raises(SettingsValidationError, match="different roots"):
        RuntimeSettings.private_local(
            ephemeral_root=tmp_path / "public",
            private_data_root=tmp_path / "public" / "private-data",
        )


def test_repository_root_and_descendant_runtime_roots_are_rejected():
    with pytest.raises(SettingsValidationError, match="repository root"):
        RuntimeSettings(ephemeral_root=ROOT)
    with pytest.raises(SettingsValidationError, match="repository root"):
        RuntimeSettings(ephemeral_root=ROOT / "runs" / "attempt")


def test_generated_run_roots_are_unique_and_run_scoped(tmp_path: Path):
    settings = RuntimeSettings(ephemeral_root=tmp_path / "runtime")
    first = settings.create_run_roots()
    second = settings.create_run_roots()

    assert first.run_id != second.run_id
    assert first.run_root == settings.ephemeral_root / first.run_id
    assert second.run_root == settings.ephemeral_root / second.run_id
    assert first.run_root.is_relative_to(settings.ephemeral_root)
    assert second.run_root.is_relative_to(settings.ephemeral_root)


def test_required_run_subdirectories_are_created(tmp_path: Path):
    roots = RuntimeSettings(ephemeral_root=tmp_path / "runtime").create_run_roots()

    assert roots.inputs.is_dir()
    assert roots.normalized.is_dir()
    assert roots.artifacts.is_dir()
    assert roots.telemetry.is_dir()
    assert sorted(path.name for path in roots.run_root.iterdir()) == [
        "artifacts",
        "inputs",
        "normalized",
        "telemetry",
    ]


def test_user_controlled_traversal_cannot_become_storage_path(tmp_path: Path):
    roots = RuntimeSettings(ephemeral_root=tmp_path / "runtime").create_run_roots()
    source = UploadedSource.from_upload("../../secret.csv", media_type="text/csv")

    storage_path = source.input_storage_path(roots, suffix=".csv")

    assert source.original_display_name == "../../secret.csv"
    assert storage_path.parent == roots.inputs
    assert storage_path.name.startswith("SRC-")
    assert storage_path.name.endswith(".csv")
    assert ".." not in storage_path.parts
    assert "secret" not in storage_path.name


def test_public_facing_errors_do_not_reveal_absolute_paths(tmp_path: Path):
    public_root = tmp_path / "public"
    private_root = public_root / "private-data"

    with pytest.raises(SettingsValidationError) as exc_info:
        RuntimeSettings.private_local(
            ephemeral_root=public_root,
            private_data_root=private_root,
        )

    message = str(exc_info.value)
    assert str(public_root) not in message
    assert str(private_root) not in message
    assert "ephemeral_root" in message
    assert "private_data_root" in message
