from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCANNER = PROJECT_ROOT / "scripts" / "public_release_scan.py"
POLICY = PROJECT_ROOT / "configs" / "release_scan.v1.json"


def _write_policy(
    root: Path,
    mutate: Callable[[dict[str, Any]], None] | None = None,
) -> Path:
    target = root / "configs" / "release_scan.v1.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    policy: dict[str, Any] = json.loads(POLICY.read_text(encoding="utf-8"))
    if mutate is not None:
        mutate(policy)
    target.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
    return target


def _minimal_repository(tmp_path: Path) -> Path:
    root = tmp_path / "release-candidate"
    root.mkdir()
    _write_policy(root)
    (root / "README.md").write_text("Synthetic public fixture.\n", encoding="utf-8")
    return root


def _run(root: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCANNER), str(root), *extra],
        check=False,
        capture_output=True,
        text=True,
    )


def _assert_blocked(result: subprocess.CompletedProcess[str], code: str) -> None:
    assert result.returncode != 0
    assert f"[{code}]" in result.stdout
    assert result.stderr == ""


def test_clean_minimal_repository_passes(tmp_path: Path):
    result = _run(_minimal_repository(tmp_path))
    assert result.returncode == 0
    assert result.stdout == "Public release scan passed\n"
    assert result.stderr == ""


def test_current_public_repository_passes():
    result = _run(PROJECT_ROOT)
    assert result.returncode == 0, result.stdout
    assert result.stdout == "Public release scan passed\n"


def test_forbidden_path_segment_is_blocked(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    target = root / ("pri" + "vate") / "rows.csv"
    target.parent.mkdir()
    target.write_text("quantity\n1\n", encoding="utf-8")
    _assert_blocked(_run(root), "FORBIDDEN_PATH_SEGMENT")


def test_forbidden_filename_pattern_is_blocked(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    (root / "reviewer-notes.txt").write_text("synthetic fixture\n", encoding="utf-8")
    _assert_blocked(_run(root), "FORBIDDEN_FILENAME")


def test_forbidden_extension_is_blocked(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    (root / "bundle.zip").write_text("not an archive\n", encoding="utf-8")
    _assert_blocked(_run(root), "FORBIDDEN_EXTENSION")


def test_zip_signature_renamed_as_csv_is_blocked(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    payload = b"P" + b"K" + bytes((3, 4)) + b"synthetic"
    (root / "renamed.csv").write_bytes(payload)
    _assert_blocked(_run(root), "ARCHIVE_MAGIC")


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("pdf", b"%" + b"PDF" + b"-1.7\n"),
        ("office", bytes.fromhex("d0cf11e0a1b11ae1") + b"synthetic"),
        ("gzip", bytes((31, 139, 8)) + b"synthetic"),
        ("seven", bytes.fromhex("377abcaf271c") + b"synthetic"),
    ],
)
def test_document_and_archive_magic_is_blocked_when_renamed(
    tmp_path: Path, name: str, payload: bytes
):
    root = _minimal_repository(tmp_path)
    (root / f"{name}.csv").write_bytes(payload)
    result = _run(root)
    assert result.returncode != 0
    assert "[ARCHIVE_MAGIC]" in result.stdout or "[DOCUMENT_MAGIC]" in result.stdout


def test_tar_magic_is_blocked_when_renamed(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    payload = bytearray(512)
    payload[257:262] = b"u" + b"star"
    (root / "renamed.csv").write_bytes(payload)
    _assert_blocked(_run(root), "ARCHIVE_MAGIC")


def test_nested_archive_payload_is_blocked(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    archive = b"P" + b"K" + bytes((3, 4)) + b"payload"
    (root / "wrapped.dat").write_bytes(b"synthetic wrapper" + archive)
    _assert_blocked(_run(root), "ARCHIVE_MAGIC")


def test_oversized_file_is_blocked(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    with (root / "large.txt").open("wb") as handle:
        handle.seek(10 * 1024 * 1024)
        handle.write(b"x")
    _assert_blocked(_run(root), "FILE_TOO_LARGE")


def test_synthetic_openai_key_is_blocked_without_echo(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    value = "s" + "k" + "-" + "A" * 32
    (root / "notes.txt").write_text(value + "\n", encoding="utf-8")
    result = _run(root)
    _assert_blocked(result, "SECRET_OPENAI_KEY")
    assert value not in result.stdout


def test_synthetic_aws_key_is_blocked(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    value = "A" + "KIA" + "0" * 16
    (root / "notes.txt").write_text(value + "\n", encoding="utf-8")
    _assert_blocked(_run(root), "SECRET_AWS_ACCESS_KEY")


def test_synthetic_github_token_is_blocked(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    value = "g" + "hp" + "_" + "a" * 36
    (root / "notes.txt").write_text(value + "\n", encoding="utf-8")
    _assert_blocked(_run(root), "SECRET_GITHUB_TOKEN")


def test_private_key_header_is_blocked(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    value = "-----" + "BEGIN " + "PRIVATE " + "KEY" + "-----"
    (root / "notes.txt").write_text(value + "\n", encoding="utf-8")
    _assert_blocked(_run(root), "SECRET_PRIVATE_KEY")


@pytest.mark.parametrize("name", ["API" + "_KEY", "SERVICE_" + "API_KEY"])
def test_non_placeholder_environment_secret_assignment_is_blocked(tmp_path: Path, name: str):
    root = _minimal_repository(tmp_path)
    value = "synthetic-credential-" + "z" * 24
    (root / ".env.example").write_text(f"{name}={value}\n", encoding="utf-8")
    result = _run(root)
    _assert_blocked(result, "SECRET_API_KEY_ASSIGNMENT")
    assert value not in result.stdout


def test_env_example_placeholder_remains_allowed(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    name = "SERVICE_" + "API_KEY"
    placeholder = "$" + "{" + name + "}"
    (root / ".env.example").write_text(f"{name}={placeholder}\n", encoding="utf-8")
    assert _run(root).returncode == 0


def test_bearer_assignment_and_header_are_blocked(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    assignment = "AUTH_" + "TOKEN" + "=" + "b" * 28
    bearer = "Bear" + "er " + "c" * 28
    (root / "notes.txt").write_text(f"{assignment}\n{bearer}\n", encoding="utf-8")
    result = _run(root)
    _assert_blocked(result, "SECRET_TOKEN_ASSIGNMENT")
    assert "[SECRET_BEARER_VALUE]" in result.stdout


@pytest.mark.parametrize(
    ("code", "path_value"),
    [
        ("ABSOLUTE_MACOS_PATH", "/" + "Users" + "/example/work/file.csv"),
        ("ABSOLUTE_LINUX_PATH", "/" + "home" + "/example/work/file.csv"),
        ("ABSOLUTE_PRIVATE_PATH", "/" + "private" + "/var/example.csv"),
        ("ABSOLUTE_TEMP_PATH", "/" + "tmp" + "/example.csv"),
        ("ABSOLUTE_WINDOWS_DRIVE_PATH", "C" + ":" + "\\" + "work\\file.csv"),
        ("ABSOLUTE_UNC_PATH", "\\" * 2 + "server\\share\\file.csv"),
    ],
)
def test_absolute_local_paths_are_blocked(tmp_path: Path, code: str, path_value: str):
    root = _minimal_repository(tmp_path)
    (root / "notes.txt").write_text(path_value + "\n", encoding="utf-8")
    result = _run(root)
    _assert_blocked(result, code)
    assert path_value not in result.stdout


def test_configured_known_private_sha256_is_blocked(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    payload = b"synthetic hash-only fixture\n"
    digest = hashlib.sha256(payload).hexdigest()

    def add_hash(policy: dict[str, Any]) -> None:
        policy["known_private_sha256"] = [digest]

    _write_policy(root, add_hash)
    (root / "candidate.txt").write_bytes(payload)
    result = _run(root)
    _assert_blocked(result, "KNOWN_PRIVATE_HASH")
    assert digest not in result.stdout


def test_empty_known_private_hash_list_works(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    policy = json.loads((root / "configs" / "release_scan.v1.json").read_text())
    assert policy["known_private_sha256"] == []
    assert _run(root).returncode == 0


def test_escaping_symlink_is_blocked_without_following_it(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside synthetic fixture\n", encoding="utf-8")
    (root / "redirect.txt").symlink_to(outside)
    _assert_blocked(_run(root), "SYMLINK_REJECTED")


def test_internal_symlink_is_explicitly_rejected(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    (root / "alias.md").symlink_to(root / "README.md")
    _assert_blocked(_run(root), "SYMLINK_REJECTED")


def test_malformed_configuration_fails_closed(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    (root / "configs" / "release_scan.v1.json").write_text("{\n", encoding="utf-8")
    _assert_blocked(_run(root), "CONFIG_INVALID")


def test_unsupported_configuration_version_fails_closed(tmp_path: Path):
    root = _minimal_repository(tmp_path)

    def change_version(policy: dict[str, Any]) -> None:
        policy["config_version"] = "999.0.0"

    _write_policy(root, change_version)
    _assert_blocked(_run(root), "CONFIG_INVALID")


def test_findings_are_deterministic_and_sorted(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    (root / "z-last.pdf").write_text("synthetic\n", encoding="utf-8")
    (root / "a-first.zip").write_text("synthetic\n", encoding="utf-8")
    first = _run(root)
    second = _run(root)
    assert first.stdout == second.stdout
    finding_lines = [line for line in first.stdout.splitlines() if line.startswith("- ")]
    paths = [line[2:].split(" [", maxsplit=1)[0] for line in finding_lines]
    assert paths == sorted(paths)


def test_output_never_reveals_matched_secret_values(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    values = [
        "s" + "k" + "-" + "Q" * 32,
        "g" + "hp" + "_" + "q" * 36,
        "A" + "KIA" + "9" * 16,
    ]
    (root / "notes.txt").write_text("\n".join(values) + "\n", encoding="utf-8")
    result = _run(root)
    assert result.returncode != 0
    assert all(value not in result.stdout for value in values)


def test_excluded_generated_directories_are_skipped_only_as_configured(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    cache = root / ".pytest_cache"
    cache.mkdir()
    value = "s" + "k" + "-" + "D" * 32
    (cache / "generated.txt").write_text(value + "\n", encoding="utf-8")
    assert _run(root).returncode == 0

    def remove_cache(policy: dict[str, Any]) -> None:
        policy["excluded_generated_directories"].remove(".pytest_cache")

    _write_policy(root, remove_cache)
    _assert_blocked(_run(root), "SECRET_OPENAI_KEY")


def test_forbidden_file_hidden_below_several_directories_is_found(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    target = root / "one" / "two" / ("pri" + "vate") / "three" / "rows.csv"
    target.parent.mkdir(parents=True)
    target.write_text("quantity\n1\n", encoding="utf-8")
    _assert_blocked(_run(root), "FORBIDDEN_PATH_SEGMENT")


def test_nonexistent_and_symlink_scan_roots_fail_closed(tmp_path: Path):
    missing = tmp_path / "missing"
    _assert_blocked(_run(missing), "UNSAFE_SCAN_ROOT")

    root = _minimal_repository(tmp_path)
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(root, target_is_directory=True)
    _assert_blocked(_run(linked_root), "UNSAFE_SCAN_ROOT")


def test_malformed_text_and_unclassified_binary_are_blocked(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    (root / "invalid.csv").write_bytes(bytes((255, 254, 253)))
    (root / "unknown.blob").write_bytes(b"synthetic" + bytes((0, 1)))
    result = _run(root)
    _assert_blocked(result, "TEXT_DECODE_ERROR")
    assert "[SUSPICIOUS_BINARY_FILE]" in result.stdout


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics are required")
def test_unreadable_file_is_blocked(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    target = root / "unreadable.txt"
    target.write_text("synthetic\n", encoding="utf-8")
    target.chmod(0)
    try:
        result = _run(root)
    finally:
        target.chmod(0o600)
    _assert_blocked(result, "UNREADABLE_ENTRY")


def test_policy_path_outside_scan_root_is_rejected(tmp_path: Path):
    root = _minimal_repository(tmp_path)
    outside_policy = tmp_path / "outside-policy.json"
    shutil.copyfile(POLICY, outside_policy)
    _assert_blocked(_run(root, "--config", str(outside_policy)), "CONFIG_INVALID")
