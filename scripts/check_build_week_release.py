#!/usr/bin/env python3
"""Audit the local Build Week release package without network access or mutation."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Final

PROJECT_ROOT: Final = Path(__file__).resolve().parents[1]

REQUIRED_FILES: Final = (
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "docs/BUILD_WEEK_PROVENANCE.md",
    "docs/JUDGING_GUIDE.md",
    "docs/ARCHITECTURE.md",
    "docs/STREAMLIT_DEPLOYMENT.md",
    "submission/DEVPOST_SUBMISSION.md",
    "submission/VIDEO_SCRIPT.md",
    "submission/VIDEO_SHOTLIST.md",
    "submission/EXTERNAL_RELEASE_CHECKLIST.md",
    "submission/TESTING_INSTRUCTIONS.md",
    "submission/RELEASE_MANIFEST.json",
    "scripts/check_build_week_release.py",
    "tests/release/test_build_week_release.py",
    "streamlit_app.py",
)

RELEASE_DOCUMENTS: Final = (
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "docs/BUILD_WEEK_PROVENANCE.md",
    "docs/JUDGING_GUIDE.md",
    "docs/ARCHITECTURE.md",
    "docs/STREAMLIT_DEPLOYMENT.md",
    "submission/DEVPOST_SUBMISSION.md",
    "submission/VIDEO_SCRIPT.md",
    "submission/VIDEO_SHOTLIST.md",
    "submission/EXTERNAL_RELEASE_CHECKLIST.md",
    "submission/TESTING_INSTRUCTIONS.md",
)

JSON_FILES: Final = (
    "demo_assets/scenario_catalog.v1.json",
    "demo_assets/benchmark_summary.v1.json",
    "submission/RELEASE_MANIFEST.json",
)

DATASET_FILES: Final[dict[str, str]] = {
    "stable_symmetric": "data/public_synthetic/stable_symmetric.csv",
    "heavy_tail_particulate": "data/public_synthetic/heavy_tail_particulate.csv",
    "batch_drift_change_point": "data/public_synthetic/batch_drift_change_point.csv",
}

EXPECTED_SCENARIOS: Final[dict[str, dict[str, object]]] = {
    "stable_symmetric": {
        "scenario_version": "1.0.0",
        "dataset_sha256": "61406ba1733671cbe91350925e4e23a011bbd6b49c90d9d59ab16a74c23c8b5f",
        "action_state": "pilot_range_supported",
        "pilot_min": 0.15,
        "pilot_max": 0.4,
        "unit": "mL",
    },
    "heavy_tail_particulate": {
        "scenario_version": "1.0.0",
        "dataset_sha256": "9e92d093d625de0df94c201daed84752a73791ce07eda92a16e39b9a7e22562f",
        "action_state": "pilot_only_conservative",
        "pilot_min": 0.05,
        "pilot_max": 0.14,
        "unit": "mL",
    },
    "batch_drift_change_point": {
        "scenario_version": "1.0.0",
        "dataset_sha256": "fe3a280f6bd084e59b533083d97826d719eec58b8c01840102a6367a455abf24",
        "action_state": "diagnose_process_first",
        "pilot_min": None,
        "pilot_max": None,
        "unit": "mL",
    },
}

EXPECTED_DEPENDENCY_HASHES: Final = {
    "pyproject.toml": "33e168cbf2acd8e8bc596224e2374e31845cb968e10fcafa9894916ac0bf9d37",
    "requirements.in": "2c5279a5518d36b65da767e8d0d9e7004592b568b6b7372f9f2b7f8040fd7435",
    "requirements.lock": "82116ddca67ef3da9b8bbf54942eb186cfcf6ace0b284dfdeabba9644effb76e",
}

EXPECTED_MACRO_COMMITS: Final = {
    "MACRO-01": "a4f67564b8d23c6a62cb747e3b54c080366486dd",
    "MACRO-02": "fe56580766b14b70da8efb047d996480fd3371de",
    "MACRO-03": "61f8f15dfa1bc0e47c1a1d2f75fea135299fc3b2",
    "MACRO-04": "e0fad6869b160988a03b44256b2de6ab72829a2c",
    "MACRO-05": "afbbae5d0f597a973cb6c8a265677c7b0d839f25",
}

README_HEADINGS: Final = (
    "# RIEC Guard",
    "## Product summary",
    "## Working demo",
    "## Three-scenario walkthrough",
    "## Architecture",
    "## GPT-5.6 role",
    "## Codex collaboration",
    "## Build Week provenance",
    "## Quick start",
    "## Live GPT setup",
    "## Testing",
    "## Privacy and limitations",
    "## Repository map",
    "## License",
)

README_REQUIRED_TEXT: Final = (
    "Auditable decisions from conflicting evidence.",
    "streamlit_app.py",
    "pilot_range_supported",
    "pilot_only_conservative",
    "diagnose_process_first",
    "GPT-5.6",
    "Codex",
    "BUILD_WEEK_PROVENANCE.md",
    "MIT",
)

COMPLETION_CLAIMS: Final = (
    "project has been submitted",
    "devpost submission is complete",
    "devpost has been submitted",
    "public deployment is live",
    "working demo is deployed",
    "youtube video has been uploaded",
    "repository has been pushed",
)

PROHIBITED_POSITIVE_CLAIMS: Final = (
    "riec guard is a production setpoint",
    "riec guard is a safety determination",
    "riec guard is a compliance determination",
    "riec guard guarantees savings",
    "riec guard has achieved savings",
    "riec guard guarantees zero risk",
    "riec guard is universally validated",
)

PRIVATE_REFERENCE_NAMES: Final = tuple(
    "_".join(parts)
    for parts in (
        ("private", "local", "reference"),
        ("original", "phase", "packages"),
        ("frozen", "reference", "specs"),
        ("official", "rules", "reference"),
        ("original", "project", "archives"),
    )
)

_WORD_PATTERN: Final = re.compile(r"[A-Za-z0-9]+(?:[-'][A-Za-z0-9]+)*")
_URL_PATTERN: Final = re.compile(r"https?://[^\s)>]+", re.IGNORECASE)
_WINDOWS_PATH_PATTERN: Final = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:\\[^\s\"'<>]+")
_SECRET_PATTERNS: Final = (
    re.compile(r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    re.compile(r"-----BEGIN[ ](?:RSA[ ]|EC[ ]|OPENSSH[ ]|DSA[ ]|PGP[ ])?PRIVATE[ ]KEY-----"),
)


class ReleaseAuditError(RuntimeError):
    """One or more deterministic release checks failed."""

    def __init__(self, failures: tuple[str, ...]) -> None:
        super().__init__("; ".join(failures))
        self.failures = failures


def sha256_file(relative: str) -> str:
    """Return the SHA-256 of one fixed repository-relative file."""

    return hashlib.sha256((PROJECT_ROOT / relative).read_bytes()).hexdigest()


def video_spoken_word_count(text: str) -> int:
    """Count only the primary voiceover enclosed by deterministic markers."""

    start_marker = "<!-- SPOKEN SCRIPT START -->"
    end_marker = "<!-- SPOKEN SCRIPT END -->"
    if text.count(start_marker) != 1 or text.count(end_marker) != 1:
        raise ValueError("video script must contain one spoken-script marker pair")
    spoken = text.split(start_marker, 1)[1].split(end_marker, 1)[0]
    return len(_WORD_PATTERN.findall(spoken))


def run_release_audit() -> tuple[str, ...]:
    """Run the complete read-only local release audit or raise stable failures."""

    failures: list[str] = []
    texts: dict[str, str] = {}
    parsed_json: dict[str, object] = {}

    for relative in REQUIRED_FILES:
        if not (PROJECT_ROOT / relative).is_file():
            failures.append(f"required file missing: {relative}")

    for relative in RELEASE_DOCUMENTS:
        path = PROJECT_ROOT / relative
        if not path.is_file():
            continue
        try:
            texts[relative] = path.read_bytes().decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            failures.append(f"document is not valid UTF-8: {relative}")

    for relative in JSON_FILES:
        path = PROJECT_ROOT / relative
        if not path.is_file():
            failures.append(f"JSON file missing: {relative}")
            continue
        try:
            text = path.read_bytes().decode("utf-8", errors="strict")
            parsed_json[relative] = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError):
            failures.append(f"JSON is not valid canonical UTF-8 JSON: {relative}")

    _check_readme(texts.get("README.md", ""), failures)
    _check_license(texts.get("LICENSE", ""), failures)
    _check_scenarios(parsed_json, failures)
    _check_manifest(parsed_json.get("submission/RELEASE_MANIFEST.json"), failures)
    _check_video(texts.get("submission/VIDEO_SCRIPT.md", ""), failures)
    _check_documents(texts, failures)
    _check_deployment_and_external_checklist(texts, failures)
    _check_dependencies(failures)

    if failures:
        raise ReleaseAuditError(tuple(sorted(set(failures))))
    return (
        "required files",
        "README and license",
        "recorded scenarios and manifest",
        "video bounds",
        "public document boundary",
        "deployment and external checklist",
        "frozen dependencies",
    )


def _check_readme(text: str, failures: list[str]) -> None:
    for heading in README_HEADINGS:
        if heading not in text:
            failures.append(f"README heading missing: {heading}")
    for required in README_REQUIRED_TEXT:
        if required not in text:
            failures.append(f"README required text missing: {required}")
    if "Deterministic code owns every numerical result and action." not in text:
        failures.append("README deterministic ownership statement missing")
    if "192" not in text or "1,056" not in text or "1%" not in text:
        failures.append("README Codex blocker account is incomplete")


def _check_license(text: str, failures: list[str]) -> None:
    if not text.lstrip().startswith("MIT License\n"):
        failures.append("LICENSE is not the preserved MIT License")
    if "Copyright (c) 2026 RIEC Guard contributors" not in text:
        failures.append("LICENSE copyright does not match the accepted baseline")


def _check_scenarios(parsed: dict[str, object], failures: list[str]) -> None:
    catalog = parsed.get("demo_assets/scenario_catalog.v1.json")
    summary = parsed.get("demo_assets/benchmark_summary.v1.json")
    if not isinstance(catalog, dict) or not isinstance(summary, dict):
        return
    catalog_rows = catalog.get("scenarios")
    summary_rows = summary.get("scenarios")
    if not isinstance(catalog_rows, list) or not isinstance(summary_rows, list):
        failures.append("recorded scenario assets do not contain scenario lists")
        return
    catalog_by_id = _rows_by_scenario_id(catalog_rows)
    summary_by_id = _rows_by_scenario_id(summary_rows)
    if set(catalog_by_id) != set(EXPECTED_SCENARIOS) or set(summary_by_id) != set(
        EXPECTED_SCENARIOS
    ):
        failures.append("recorded assets are not the fixed three-scenario set")
        return
    for scenario_id, expected in EXPECTED_SCENARIOS.items():
        catalog_row = catalog_by_id[scenario_id]
        summary_row = summary_by_id[scenario_id]
        expectation = catalog_row.get("expectation")
        if not isinstance(expectation, dict):
            failures.append(f"catalog expectation missing: {scenario_id}")
            continue
        observed = {
            "scenario_version": summary_row.get("scenario_version"),
            "dataset_sha256": summary_row.get("dataset_sha256"),
            "action_state": summary_row.get("action_state"),
            "pilot_min": summary_row.get("pilot_min"),
            "pilot_max": summary_row.get("pilot_max"),
            "unit": summary_row.get("unit"),
        }
        if observed != expected or expectation.get("action_state") != expected["action_state"]:
            failures.append(f"recorded scenario outcome mismatch: {scenario_id}")
        if sha256_file(DATASET_FILES[scenario_id]) != expected["dataset_sha256"]:
            failures.append(f"dataset SHA-256 mismatch: {scenario_id}")


def _rows_by_scenario_id(rows: list[object]) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        scenario_id = row.get("scenario_id")
        if isinstance(scenario_id, str):
            result[scenario_id] = row
    return result


def _check_manifest(value: object, failures: list[str]) -> None:
    if not isinstance(value, dict):
        failures.append("release manifest is not an object")
        return
    expected_scalars = {
        "manifest_version": "1.0.0",
        "project_name": "RIEC Guard",
        "track": "Work & Productivity",
        "branch": "build-week-2026",
        "accepted_baseline_commit": "afbbae5d0f597a973cb6c8a265677c7b0d839f25",
        "intended_release_tag": "build-week-2026-submission-v1",
        "python_version": "3.12.13",
        "streamlit_version": "1.59.2",
        "openai_sdk_version": "2.46.0",
        "default_gpt_model": "gpt-5.6",
        "public_entry_point": "streamlit_app.py",
        "license_identifier": "MIT",
    }
    for key, expected in expected_scalars.items():
        if value.get(key) != expected:
            failures.append(f"release manifest field mismatch: {key}")
    if value.get("macro_commits") != EXPECTED_MACRO_COMMITS:
        failures.append("release manifest macro commits mismatch")
    if value.get("prompt_versions") != [
        "contract-assistant.v1",
        "decision-memo.v1",
        "claim-auditor.v1",
    ]:
        failures.append("release manifest prompt versions mismatch")
    scenarios = value.get("scenarios")
    if not isinstance(scenarios, list):
        failures.append("release manifest scenarios missing")
    else:
        rows = _rows_by_scenario_id(scenarios)
        observed = {
            scenario_id: {key: row.get(key) for key in expected}
            for scenario_id, expected in EXPECTED_SCENARIOS.items()
            if (row := rows.get(scenario_id)) is not None
        }
        if observed != EXPECTED_SCENARIOS:
            failures.append("release manifest scenario records mismatch")
    actions = value.get("external_actions")
    if (
        not isinstance(actions, list)
        or not actions
        or any(
            not isinstance(item, dict) or item.get("status") != "human_required" for item in actions
        )
    ):
        failures.append("release manifest external actions are not all human_required")
    manifest_path = PROJECT_ROOT / "submission/RELEASE_MANIFEST.json"
    if manifest_path.is_file():
        expected_bytes = (
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        if manifest_path.read_bytes() != expected_bytes:
            failures.append("release manifest formatting is not sorted and stable")


def _check_video(text: str, failures: list[str]) -> None:
    try:
        word_count = video_spoken_word_count(text)
    except ValueError:
        failures.append("video script spoken-word markers are invalid")
        return
    if not 320 <= word_count <= 390:
        failures.append(f"video script spoken word count outside 320-390: {word_count}")
    folded = text.casefold()
    for required in ("codex", "gpt-5.6", "working product", "deterministic"):
        if required not in folded:
            failures.append(f"video script required concept missing: {required}")
    fixture_sentence = (
        "This offline fixture demonstrates the structured workflow without making an API request."
    )
    if fixture_sentence not in text:
        failures.append("video script required offline fixture sentence missing")


def _check_documents(texts: dict[str, str], failures: list[str]) -> None:
    macos_prefix = "/" + "Users" + "/"
    unix_home_prefix = "/" + "home" + "/"
    for relative, text in texts.items():
        folded = text.casefold()
        if macos_prefix.casefold() in folded or unix_home_prefix in folded:
            failures.append(f"absolute local path found: {relative}")
        if _WINDOWS_PATH_PATTERN.search(text):
            failures.append(f"absolute Windows path found: {relative}")
        for match in _URL_PATTERN.findall(text):
            if not match.casefold().startswith(("http://127.0.0.1", "http://localhost")):
                failures.append(f"external or fabricated URL found: {relative}")
        for pattern in _SECRET_PATTERNS:
            if pattern.search(text):
                failures.append(f"secret-shaped value found: {relative}")
        if any(name in folded for name in PRIVATE_REFERENCE_NAMES):
            failures.append(f"private or historical reference name found: {relative}")
        if "begin full prompt" in folded or re.search(
            r"^chain[- ]of[- ]thought\s*:", text, re.I | re.M
        ):
            failures.append(f"full prompt or chain-of-thought material found: {relative}")
        if any(claim in folded for claim in COMPLETION_CLAIMS):
            failures.append(f"completed external-action claim found: {relative}")
        if any(claim in folded for claim in PROHIBITED_POSITIVE_CLAIMS):
            failures.append(f"prohibited product claim found: {relative}")


def _check_deployment_and_external_checklist(texts: dict[str, str], failures: list[str]) -> None:
    deployment = texts.get("docs/STREAMLIT_DEPLOYMENT.md", "")
    if "build-week-2026" not in deployment or "streamlit_app.py" not in deployment:
        failures.append("deployment documentation lacks the exact branch or entry point")
    checklist = texts.get("submission/EXTERNAL_RELEASE_CHECKLIST.md", "").casefold()
    for required in ("/feedback", "github", "streamlit", "youtube", "devpost"):
        if required not in checklist:
            failures.append(f"external checklist item missing: {required}")


def _check_dependencies(failures: list[str]) -> None:
    for relative, expected in EXPECTED_DEPENDENCY_HASHES.items():
        path = PROJECT_ROOT / relative
        if not path.is_file() or sha256_file(relative) != expected:
            failures.append(f"dependency file changed from MACRO-05: {relative}")


def main() -> int:
    try:
        checks = run_release_audit()
    except ReleaseAuditError as exc:
        print("Build Week release check failed:", file=sys.stderr)
        for failure in exc.failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    except (OSError, TypeError, ValueError):
        print("Build Week release check failed safely", file=sys.stderr)
        return 2
    print(f"Build Week release check passed: {len(checks)} check groups")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
