from __future__ import annotations

import ast
import importlib.util
import json
import socket
from pathlib import Path
from types import ModuleType
from typing import Any

import openai
import pytest

ROOT = Path(__file__).resolve().parents[2]
RELEASE_CHECK = ROOT / "scripts" / "check_build_week_release.py"
README = ROOT / "README.md"
MANIFEST = ROOT / "submission" / "RELEASE_MANIFEST.json"
SUMMARY = ROOT / "demo_assets" / "benchmark_summary.v1.json"
VIDEO = ROOT / "submission" / "VIDEO_SCRIPT.md"
LICENSE = ROOT / "LICENSE"


def _load_release_check() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_riec_guard_release_check", RELEASE_CHECK)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_release_audit_passes() -> None:
    module = _load_release_check()

    assert module.run_release_audit() == (
        "required files",
        "README and license",
        "recorded scenarios and manifest",
        "video bounds",
        "public document boundary",
        "deployment and external checklist",
        "frozen dependencies",
    )


def test_readme_has_all_judge_facing_sections() -> None:
    module = _load_release_check()
    text = README.read_text(encoding="utf-8")

    assert all(heading in text for heading in module.README_HEADINGS)
    assert all(required in text for required in module.README_REQUIRED_TEXT)
    assert "Deterministic code owns every numerical result and action." in text


def test_recorded_scenario_and_manifest_values_are_consistent() -> None:
    module = _load_release_check()
    manifest = _json(MANIFEST)
    summary = _json(SUMMARY)
    manifest_rows = {
        row["scenario_id"]: row
        for row in manifest["scenarios"]
        if isinstance(row, dict) and isinstance(row.get("scenario_id"), str)
    }
    summary_rows = {
        row["scenario_id"]: row
        for row in summary["scenarios"]
        if isinstance(row, dict) and isinstance(row.get("scenario_id"), str)
    }

    assert set(manifest_rows) == set(module.EXPECTED_SCENARIOS)
    assert set(summary_rows) == set(module.EXPECTED_SCENARIOS)
    for scenario_id, expected in module.EXPECTED_SCENARIOS.items():
        for key, value in expected.items():
            assert manifest_rows[scenario_id][key] == value
            assert summary_rows[scenario_id][key] == value
        assert module.sha256_file(module.DATASET_FILES[scenario_id]) == expected["dataset_sha256"]


def test_manifest_is_sorted_stable_and_external_actions_are_human_required() -> None:
    raw = MANIFEST.read_bytes()
    manifest = _json(MANIFEST)

    assert (
        raw == (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    )
    assert manifest["intended_release_tag"] == "build-week-2026-submission-v1"
    assert manifest["license_identifier"] == "MIT"
    assert all(
        isinstance(action, dict) and action.get("status") == "human_required"
        for action in manifest["external_actions"]
    )


def test_video_script_spoken_word_count_and_required_boundary_are_bounded() -> None:
    module = _load_release_check()
    text = VIDEO.read_text(encoding="utf-8")
    count = module.video_spoken_word_count(text)

    assert 320 <= count <= 390
    assert "Codex" in text
    assert "GPT-5.6" in text
    assert "working product" in text.casefold()
    assert "deterministic" in text.casefold()
    assert (
        "This offline fixture demonstrates the structured workflow without making an API request."
        in text
    )


def test_public_documents_have_no_paths_secrets_fake_urls_or_prohibited_claims() -> None:
    module = _load_release_check()
    texts = {
        relative: (ROOT / relative).read_text(encoding="utf-8")
        for relative in module.RELEASE_DOCUMENTS
    }
    failures: list[str] = []

    module._check_documents(texts, failures)

    assert failures == []


def test_preserved_mit_license_exists() -> None:
    text = LICENSE.read_text(encoding="utf-8")

    assert text.lstrip().startswith("MIT License\n")
    assert "Copyright (c) 2026 RIEC Guard contributors" in text


def test_release_checker_import_and_audit_make_no_network_or_api_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("network or live API construction is forbidden in the release audit")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(openai, "OpenAI", forbidden)

    module = _load_release_check()

    assert module.run_release_audit()


def test_release_checker_source_has_no_network_client_import() -> None:
    tree = ast.parse(RELEASE_CHECK.read_text(encoding="utf-8"))
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert imported_roots.isdisjoint(
        {"http", "httpx", "openai", "requests", "socket", "urllib", "websockets"}
    )


def test_streamlit_entry_import_does_not_construct_openai_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("OpenAI client construction is forbidden during import")

    monkeypatch.setattr(openai, "OpenAI", forbidden)
    entry = ROOT / "streamlit_app.py"
    spec = importlib.util.spec_from_file_location("_riec_guard_release_entry", entry)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)

    spec.loader.exec_module(module)

    assert callable(module.main)
