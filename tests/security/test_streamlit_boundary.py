from __future__ import annotations

import ast
import json
import logging
import re
from dataclasses import replace
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from riec_guard.errors import ErrorEnvelope
from riec_guard.ui import app as ui_app
from riec_guard.ui import backend
from riec_guard.ui.copy import GPT_DOES_NOT_DECIDE
from riec_guard.ui.models import UiDownloadPacket, UiGptResult, UiScenarioBundle

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_APPLICATION_PATH = _REPOSITORY_ROOT / "streamlit_app.py"
_APP_TIMEOUT = 30.0
_PUBLIC_PRODUCT_FILES = (
    _REPOSITORY_ROOT / "streamlit_app.py",
    *sorted((_REPOSITORY_ROOT / "src" / "riec_guard" / "ui").glob("*.py")),
    _REPOSITORY_ROOT / ".streamlit" / "config.toml",
    _REPOSITORY_ROOT / ".streamlit" / "secrets.toml.example",
    _REPOSITORY_ROOT / "docs" / "STREAMLIT_DEPLOYMENT.md",
    _REPOSITORY_ROOT / "scripts" / "check_streamlit_app.py",
)


def _visible_text(app: AppTest) -> str:
    fragments: list[str] = []
    for group_name in (
        "title",
        "header",
        "subheader",
        "caption",
        "markdown",
        "text",
        "info",
        "success",
        "warning",
        "error",
        "metric",
    ):
        for element in getattr(app, group_name, ()):
            fragments.extend(
                str(value)
                for attribute in ("label", "value")
                if (value := getattr(element, attribute, None)) is not None
            )
    return " ".join(" ".join(fragments).split())


def _recorded_bundle() -> UiScenarioBundle:
    result = backend.load_verified_recorded_scenario("stable_symmetric")
    assert isinstance(result, UiScenarioBundle)
    return result


def _adversarial_narrative() -> UiGptResult:
    return UiGptResult(
        scenario_id="stable_symmetric",
        context_source="recorded_production_default",
        mode_label="Fixture / non-live",
        status="completed",
        user_message="Narrative available.",
        fixture_non_live=True,
        deterministic_analysis_available=True,
        requested_model="gpt-5.6",
        prompt_versions=(
            "contract-assistant.v1",
            "decision-memo.v1",
            "claim-auditor.v1",
        ),
        workflow_sha256="b" * 64,
        contract_suggestions=(),
        requires_human_confirmation=True,
        analysis_permitted=False,
        memo_title="Adversarial narrative",
        decision_snapshot="Narrative asks for an unsupported 999 mL production setting.",
        evidence_summary="Narrative cannot alter deterministic evidence.",
        protocol_explanation="Narrative cannot alter protocol output.",
        recommended_next_step="Narrative cannot alter the action.",
        memo_limitations=(
            "Synthetic fixture.",
            "Retrospective only.",
            "No production setting.",
            "Deterministic action controls.",
        ),
        findings=(),
        claim_audit_status="blocked",
        deterministic_validation_status="blocked",
        claim_reviews=(),
        referenced_evidence_ids=(),
        calls=(),
    )


def test_root_entry_point_is_narrow_and_import_has_no_runtime_side_effect_call() -> None:
    source = _APPLICATION_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=_APPLICATION_PATH.name)
    imports = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]

    assert imports == []
    assert len(tree.body) == 2
    entry_function, guard = tree.body
    assert isinstance(entry_function, ast.FunctionDef)
    assert entry_function.name == "main"
    assert entry_function.args.args == []
    assert len(entry_function.body) == 2
    lazy_import, run_call = entry_function.body
    assert isinstance(lazy_import, ast.ImportFrom)
    assert lazy_import.module == "riec_guard.ui.app"
    assert [(alias.name, alias.asname) for alias in lazy_import.names] == [("main", "run_app")]
    assert isinstance(run_call, ast.Expr)
    assert ast.unparse(run_call.value) == "run_app()"
    assert isinstance(guard, ast.If)
    assert ast.unparse(guard.test) == "__name__ == '__main__'"
    assert len(guard.body) == 1
    assert isinstance(guard.body[0], ast.Expr)
    assert ast.unparse(guard.body[0].value) == "main()"
    assert guard.orelse == []


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        (None, False),
        ("", False),
        ("true", True),
        ("1", True),
        ("yes", True),
        ("TRUE", False),
        (" yes ", False),
        ("on", False),
        ("false", False),
        ("0", False),
    ),
)
def test_recompute_enablement_uses_only_exact_environment_values(
    monkeypatch: pytest.MonkeyPatch,
    value: str | None,
    expected: bool,
) -> None:
    if value is None:
        monkeypatch.delenv("RIEC_GUARD_RECOMPUTE_ENABLED", raising=False)
    else:
        monkeypatch.setenv("RIEC_GUARD_RECOMPUTE_ENABLED", value)

    assert ui_app._recompute_enabled() is expected


def test_expensive_analysis_gpt_network_and_write_calls_are_not_at_module_scope() -> None:
    paths = (
        _REPOSITORY_ROOT / "src" / "riec_guard" / "ui" / "backend.py",
        _REPOSITORY_ROOT / "src" / "riec_guard" / "ui" / "app.py",
    )
    prohibited_calls = {
        "run_public_demo_scenario",
        "profile_dataset",
        "run_gpt_interpretation_workflow",
        "OpenAIResponsesClient",
        "OpenAI",
        "open",
        "write_text",
        "write_bytes",
    }
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
        parent_by_node: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parent_by_node[child] = parent
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else (node.func.attr if isinstance(node.func, ast.Attribute) else "")
            )
            if name not in prohibited_calls:
                continue
            ancestor = parent_by_node.get(node)
            while ancestor is not None and not isinstance(
                ancestor, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
            ):
                ancestor = parent_by_node.get(ancestor)
            assert ancestor is not None, f"{path.name}: module-scope prohibited call {name}"


def test_secret_shaped_controlled_failure_is_absent_from_render_download_and_log(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    sentinel = "RIEC_FAKE_SECRET_SHAPED_VALUE_DO_NOT_RENDER"
    local_path_sentinel = "".join(("/", "Users", "/blocked/example"))
    monkeypatch.setenv("OPENAI_API_KEY", sentinel)
    monkeypatch.setenv("RIEC_GUARD_LIVE_GPT_ENABLED", "false")

    def fail_fixture(_: str) -> UiGptResult:
        raise RuntimeError(f"transport failed with {sentinel} at {local_path_sentinel}")

    monkeypatch.setattr(backend, "run_fixture_gpt_workflow", fail_fixture)
    caplog.set_level(logging.DEBUG)
    app = AppTest.from_file(_APPLICATION_PATH, default_timeout=_APP_TIMEOUT)
    app.secrets = {"RIEC_GUARD_LIVE_GPT_ENABLED": False}
    app.run(timeout=_APP_TIMEOUT)
    app.button("fixture_gpt").click().run(timeout=_APP_TIMEOUT)

    assert len(app.exception) == 0
    visible = _visible_text(app)
    packet = backend.build_download_packet(_recorded_bundle())
    assert isinstance(packet, UiDownloadPacket)
    combined = "\n".join((visible, packet.content.decode("utf-8"), caplog.text))
    assert sentinel not in combined
    assert local_path_sentinel not in combined
    assert "Narrative assistance could not be completed safely." in visible


def test_download_rejects_cross_scenario_gpt_result_with_sanitized_error() -> None:
    bundle = _recorded_bundle()
    foreign = replace(_adversarial_narrative(), scenario_id="heavy_tail_particulate")

    result = backend.build_download_packet(bundle, gpt_result=foreign)

    assert isinstance(result, ErrorEnvelope)
    assert result.code == "UI_DOWNLOAD_INPUT_INVALID"
    assert result.safe_details == {}
    serialized = result.to_canonical_json()
    assert "Adversarial narrative" not in serialized
    assert "999" not in serialized


def test_gpt_narrative_cannot_change_deterministic_action_or_protocol_output() -> None:
    bundle = _recorded_bundle()
    narrative = _adversarial_narrative()

    packet = backend.build_download_packet(bundle, gpt_result=narrative)

    assert isinstance(packet, UiDownloadPacket)
    payload = json.loads(packet.content)
    assert payload["action"]["state"] == "pilot_range_supported"
    assert payload["action"]["pilot_min"] == 0.15
    assert payload["action"]["pilot_max"] == 0.4
    assert [row["value"] for row in payload["protocols"]] == [
        0.5999999999999943,
        0.5,
        0.5,
        0.5,
    ]
    assert payload["gpt"]["memo"]["decision_snapshot"].startswith("Narrative asks")
    assert GPT_DOES_NOT_DECIDE == (
        "GPT-5.6 does not calculate the statistical result or choose the action."
    )


def test_ui_orchestrator_keeps_deterministic_analysis_behind_backend_boundary() -> None:
    app_path = _REPOSITORY_ROOT / "src" / "riec_guard" / "ui" / "app.py"
    tree = ast.parse(app_path.read_text(encoding="utf-8"), filename=app_path.name)
    forbidden_import_roots = {
        "riec_guard.riec",
        "riec_guard.protocols",
        "riec_guard.decision",
        "riec_guard.app_service",
        "riec_guard.benchmarks.runner",
        "riec_guard.gpt",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(
                not any(alias.name.startswith(root) for root in forbidden_import_roots)
                for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            assert not any(module.startswith(root) for root in forbidden_import_roots)

    render_gpt = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_render_gpt"
    )
    called_names = {
        node.func.attr
        for node in ast.walk(render_gpt)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert "recompute_public_scenario" not in called_names
    assert "run_public_demo_scenario" not in called_names
    assert "run_grouped_riec" not in called_names


def test_new_public_product_files_have_no_private_roots_local_paths_or_positive_claims() -> None:
    missing = tuple(path for path in _PUBLIC_PRODUCT_FILES if not path.is_file())
    assert missing == ()
    forbidden_roots = (
        "_".join(("PRIVATE", "LOCAL", "REFERENCE")),
        "_".join(("ORIGINAL", "PHASE", "PACKAGES")),
        "_".join(("FROZEN", "REFERENCE", "SPECS")),
        "_".join(("OFFICIAL", "RULES", "REFERENCE")),
        "_".join(("ORIGINAL", "PROJECT", "ARCHIVES")),
        " ".join(("historical", "archive")),
    )
    local_path_patterns = (
        re.compile(r"/(?:Users|home)/[^\s'\"`]+"),
        re.compile(r"[A-Za-z]:\\Users\\"),
        re.compile(r"(?:^|\s)~/(?:[^\s'\"`]+)"),
    )
    positive_claims = (
        "safe for production",
        "safe to deploy",
        "is optimal",
        "is compliant",
        "guarantees compliance",
        "guaranteed savings",
        "achieved savings of",
        "is a production setpoint",
        "recommended production setpoint",
    )

    for path in _PUBLIC_PRODUCT_FILES:
        text = path.read_text(encoding="utf-8")
        folded = text.casefold()
        assert not any(root.casefold() in folded for root in forbidden_roots), path
        assert not any(pattern.search(text) for pattern in local_path_patterns), path
        assert not any(claim in folded for claim in positive_claims), path

    combined = "\n".join(path.read_text(encoding="utf-8") for path in _PUBLIC_PRODUCT_FILES)
    assert "retrospective screening" in combined.casefold()
    assert "not a production setpoint" in combined.casefold()
    assert "public synthetic" in combined.casefold()
