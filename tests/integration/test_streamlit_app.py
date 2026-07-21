from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
import pytest
from streamlit.testing.v1 import AppTest

from riec_guard.ui import backend
from riec_guard.ui.copy import (
    LIVE_UNAVAILABLE_MESSAGE,
    PUBLIC_RECORDED_MODE_CAPTION,
    RECOMPUTE_UNAVAILABLE_MESSAGE,
)
from riec_guard.ui.models import UiGptResult, UiScenarioBundle

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_APPLICATION_PATH = _REPOSITORY_ROOT / "streamlit_app.py"
_APP_TIMEOUT = 30.0


def _visible_text(app: AppTest) -> str:
    fragments: list[str] = []
    for group_name in (
        "title",
        "header",
        "subheader",
        "caption",
        "code",
        "markdown",
        "text",
        "info",
        "success",
        "warning",
        "error",
        "metric",
    ):
        for element in getattr(app, group_name, ()):
            for attribute in ("label", "value"):
                value = getattr(element, attribute, None)
                if value is not None:
                    fragments.append(str(value))
    return " ".join(" ".join(fragments).split())


@pytest.fixture(autouse=True)
def _clean_server_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("RIEC_GUARD_RECOMPUTE_ENABLED", raising=False)
    monkeypatch.delenv("RIEC_GUARD_LIVE_GPT_ENABLED", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)


def _app(
    *,
    live_enabled: bool = False,
    deployment_credential: str | None = None,
    recompute_secret: object | None = None,
) -> AppTest:
    app = AppTest.from_file(_APPLICATION_PATH, default_timeout=_APP_TIMEOUT)
    secrets: dict[str, object] = {"RIEC_GUARD_LIVE_GPT_ENABLED": live_enabled}
    if deployment_credential is not None:
        secrets["OPENAI_API_KEY"] = deployment_credential
    if recompute_secret is not None:
        secrets["RIEC_GUARD_RECOMPUTE_ENABLED"] = recompute_secret
    app.secrets = secrets
    app.run(timeout=_APP_TIMEOUT)
    assert len(app.exception) == 0
    return app


def _recorded_bundle(scenario_id: str) -> UiScenarioBundle:
    result = backend.load_verified_recorded_scenario(scenario_id)
    assert isinstance(result, UiScenarioBundle)
    return result


def _gpt_result(scenario_id: str, *, live: bool) -> UiGptResult:
    return UiGptResult(
        scenario_id=scenario_id,
        context_source="recorded_production_default",
        mode_label="Live GPT-5.6" if live else "Fixture / non-live",
        status="completed",
        user_message=f"Bounded {'live' if live else 'fixture'} memo completed for {scenario_id}.",
        fixture_non_live=not live,
        deterministic_analysis_available=True,
        requested_model="gpt-5.6",
        prompt_versions=(
            "contract-assistant.v1",
            "decision-memo.v1",
            "claim-auditor.v1",
        ),
        workflow_sha256="a" * 64,
        contract_suggestions=(),
        requires_human_confirmation=True,
        analysis_permitted=False,
        memo_title=f"Evidence-bound memo for {scenario_id}",
        decision_snapshot="Deterministic action remains authoritative.",
        evidence_summary="Only sanitized aggregate evidence was interpreted.",
        protocol_explanation="Protocol conflict remains visible.",
        recommended_next_step="Review the retrospective screen in a controlled pilot.",
        memo_limitations=(
            "Public synthetic mechanism only.",
            "Retrospective screening only.",
            "No production setpoint is established.",
            "Deterministic code owns the action.",
        ),
        findings=(),
        claim_audit_status="pass",
        deterministic_validation_status="passed",
        claim_reviews=(),
        referenced_evidence_ids=(),
        calls=(),
    )


def test_default_recorded_product_renders_stable_scenario_and_four_tabs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"recompute": 0, "fixture": 0, "live": 0}
    write_attempts: list[str] = []
    original_os_open = os.open
    write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND

    def guarded_os_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if flags & write_flags:
            write_attempts.append(os.fsdecode(path))
            raise AssertionError("initial app load attempted a file write")
        if dir_fd is None:
            return original_os_open(path, flags, mode)
        return original_os_open(path, flags, mode, dir_fd=dir_fd)

    def forbidden_recompute(scenario_id: str) -> UiScenarioBundle:
        calls["recompute"] += 1
        return _recorded_bundle(scenario_id)

    def forbidden_fixture(scenario_id: str) -> UiGptResult:
        calls["fixture"] += 1
        return _gpt_result(scenario_id, live=False)

    def forbidden_live(scenario_id: str, **_: object) -> UiGptResult:
        calls["live"] += 1
        return _gpt_result(scenario_id, live=True)

    monkeypatch.setattr(backend, "recompute_public_scenario", forbidden_recompute)
    monkeypatch.setattr(backend, "run_fixture_gpt_workflow", forbidden_fixture)
    monkeypatch.setattr(backend, "run_live_gpt_workflow", forbidden_live)
    monkeypatch.setattr(os, "open", guarded_os_open)

    app = _app()
    visible = _visible_text(app)

    assert calls == {"recompute": 0, "fixture": 0, "live": 0}
    assert write_attempts == []
    with pytest.raises(KeyError):
        app.button("recompute_audit")
    assert any(item.value == "RIEC Guard" for item in app.title)
    assert app.selectbox("scenario_selector").value == "stable_symmetric"
    assert [tab.label for tab in app.tabs] == ["Decision", "Evidence", "GPT-5.6", "Method"]
    assert "Recorded deterministic audit" in visible
    assert "Controlled pilot range supported" in visible
    assert "Auditable decisions from conflicting evidence." in visible
    assert "Deterministic statistics decide." in visible
    assert "Profile → Contract → RIEC → Protocols → Action → GPT memo → Claim audit" in visible
    assert PUBLIC_RECORDED_MODE_CAPTION in visible
    assert RECOMPUTE_UNAVAILABLE_MESSAGE not in visible
    assert "The deterministic audit could not be recomputed safely." not in visible
    assert len(app.error) == 0
    assert any(item.value == "M4_product_stream_shift" for item in app.code)
    assert all(item.label != "RIEC winner" for item in app.metric)
    assert "Generate offline fixture memo" == app.button("fixture_gpt").label
    assert " ".join(LIVE_UNAVAILABLE_MESSAGE.split()) in visible


def test_scenario_changes_render_heavy_tail_and_drift_without_automatic_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    automatic_calls: list[str] = []
    monkeypatch.setattr(
        backend,
        "recompute_public_scenario",
        lambda scenario_id: automatic_calls.append(f"recompute:{scenario_id}"),
    )
    monkeypatch.setattr(
        backend,
        "run_fixture_gpt_workflow",
        lambda scenario_id: automatic_calls.append(f"fixture:{scenario_id}"),
    )
    monkeypatch.setattr(
        backend,
        "run_live_gpt_workflow",
        lambda scenario_id, **_: automatic_calls.append(f"live:{scenario_id}"),
    )

    app = _app()
    selector = app.selectbox("scenario_selector")
    assert selector.options == [
        "Stable symmetric process",
        "Heavy-tail particulate variation",
        "Batch drift and change point",
    ]

    selector.select("heavy_tail_particulate").run(timeout=_APP_TIMEOUT)
    assert len(app.exception) == 0
    heavy_visible = _visible_text(app)
    assert "Heavy-tail particulate variation" in selector.options
    assert "Conservative pilot only" in heavy_visible
    assert "material" in heavy_visible
    assert any(item.value == "M4_product_stream_shift" for item in app.code)
    assert automatic_calls == []

    app.selectbox("scenario_selector").select("batch_drift_change_point").run(timeout=_APP_TIMEOUT)
    assert len(app.exception) == 0
    drift_visible = _visible_text(app)
    assert "Diagnose process first" in drift_visible
    assert "No pilot interval is supported" in drift_visible
    assert "0.00–0.00" not in drift_visible
    assert any(item.value == "M6_product_stream_shift_time" for item in app.code)
    assert automatic_calls == []


def test_demo_guide_is_collapsed_and_contains_required_public_boundaries() -> None:
    app = _app()
    guide = next(item for item in app.expander if item.label == "How to use this demo")
    visible = _visible_text(app)

    assert guide.proto.expanded is False
    for required in (
        "Stable symmetric process",
        "Heavy-tail particulate variation",
        "Batch drift and change point",
        "Decision",
        "Evidence",
        "Generate offline fixture memo",
        "Deterministic Python owns every numerical result and action.",
        "GPT-5.6 explains sanitized aggregate evidence and audits language.",
        "Raw rows are not sent to GPT.",
        "The offline fixture makes no API request.",
        "200 whole-group bootstrap replicates",
        "SHA-256",
        "retrospective screening demonstration",
        "not a production setpoint",
    ):
        assert required in visible


def test_fixture_result_is_explicit_and_cleared_when_scenario_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fixture(scenario_id: str) -> UiGptResult:
        calls.append(scenario_id)
        return _gpt_result(scenario_id, live=False)

    monkeypatch.setattr(backend, "run_fixture_gpt_workflow", fixture)
    app = _app()
    assert "Evidence-bound memo for stable_symmetric" not in _visible_text(app)

    app.button("fixture_gpt").click().run(timeout=_APP_TIMEOUT)
    assert len(app.exception) == 0
    assert calls == ["stable_symmetric"]
    assert "Fixture / non-live — completed" in _visible_text(app)
    assert "Evidence-bound memo for stable_symmetric" in _visible_text(app)

    app.selectbox("scenario_selector").select("heavy_tail_particulate").run(timeout=_APP_TIMEOUT)
    assert len(app.exception) == 0
    assert calls == ["stable_symmetric"]
    assert "Evidence-bound memo for stable_symmetric" not in _visible_text(app)
    assert "Fixture / non-live — completed" not in _visible_text(app)


def test_recompute_runs_only_after_explicit_button_and_keeps_sanitized_bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setenv("RIEC_GUARD_RECOMPUTE_ENABLED", "true")

    def recompute(scenario_id: str) -> UiScenarioBundle:
        calls.append(scenario_id)
        return replace(
            _recorded_bundle(scenario_id),
            result_source="Recomputed deterministic audit",
            source_explanation="Explicit sanitized recomputation fixture.",
        )

    monkeypatch.setattr(backend, "recompute_public_scenario", recompute)
    app = _app()
    assert calls == []

    app.selectbox("scenario_selector").select("heavy_tail_particulate").run(timeout=_APP_TIMEOUT)
    assert calls == []

    app.button("recompute_audit").click().run(timeout=_APP_TIMEOUT)
    assert len(app.exception) == 0
    assert calls == ["heavy_tail_particulate"]
    assert "Recomputed deterministic audit" in _visible_text(app)
    assert app.session_state["m05_recomputed_results"][
        "heavy_tail_particulate"
    ].definition.scenario_id == ("heavy_tail_particulate")


def test_enabled_recompute_failure_preserves_recorded_audit_with_calm_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setenv("RIEC_GUARD_RECOMPUTE_ENABLED", "true")

    def unavailable(scenario_id: str) -> UiScenarioBundle:
        calls.append(scenario_id)
        raise RuntimeError("controlled recompute failure")

    monkeypatch.setattr(backend, "recompute_public_scenario", unavailable)
    app = _app()
    assert calls == []

    app.button("recompute_audit").click().run(timeout=_APP_TIMEOUT)

    visible = _visible_text(app)
    assert len(app.exception) == 0
    assert calls == ["stable_symmetric"]
    assert "Recorded deterministic audit" in visible
    assert "Controlled pilot range supported" in visible
    assert RECOMPUTE_UNAVAILABLE_MESSAGE in visible
    assert "The deterministic audit could not be recomputed safely." not in visible
    assert len(app.error) == 0
    assert app.session_state["m05_recomputed_results"] == {}


def test_recompute_flag_cannot_be_enabled_through_streamlit_secrets() -> None:
    app = _app(recompute_secret=True)

    with pytest.raises(KeyError):
        app.button("recompute_audit")
    assert "Recorded deterministic audit" in _visible_text(app)


def test_live_unavailable_message_preserves_deterministic_and_fixture_controls() -> None:
    app = _app()
    visible = _visible_text(app)

    assert " ".join(LIVE_UNAVAILABLE_MESSAGE.split()) in visible
    assert app.button("fixture_gpt").disabled is False
    with pytest.raises(KeyError):
        app.button("live_gpt")


def test_forced_disabled_live_click_cannot_call_backend_without_acknowledgment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        backend,
        "run_live_gpt_workflow",
        lambda scenario_id, **_: calls.append(scenario_id),
    )
    app = _app(live_enabled=True, deployment_credential="server-side-test-value")
    button = app.button("live_gpt")
    assert button.label == "Generate with live GPT-5.6"
    assert button.disabled

    button.click().run(timeout=_APP_TIMEOUT)

    assert len(app.exception) == 0
    assert calls == []
    assert "requires server-side enablement" in _visible_text(app)


def test_fake_live_requires_ack_runs_once_and_isolated_by_scenario_and_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []

    def live(
        scenario_id: str,
        *,
        deployment_credential: str,
        **_: object,
    ) -> UiGptResult:
        calls.append((scenario_id, deployment_credential))
        return _gpt_result(scenario_id, live=True)

    monkeypatch.setattr(backend, "run_live_gpt_workflow", live)
    app = _app(live_enabled=True, deployment_credential="server-side-test-value")
    assert app.checkbox("live_gpt_ack").value is False
    assert app.button("live_gpt").disabled

    app.checkbox("live_gpt_ack").check().run(timeout=_APP_TIMEOUT)
    assert not app.button("live_gpt").disabled
    app.button("live_gpt").click().run(timeout=_APP_TIMEOUT)

    assert len(app.exception) == 0
    assert calls == [("stable_symmetric", "server-side-test-value")]
    assert "Live GPT-5.6 — completed" in _visible_text(app)
    assert "Model: gpt-5.6" in _visible_text(app)
    assert app.button("live_gpt").disabled
    assert app.session_state["m05_live_success_scenarios"] == ("stable_symmetric",)

    app.button("live_gpt").click().run(timeout=_APP_TIMEOUT)
    assert calls == [("stable_symmetric", "server-side-test-value")]

    assert app.button("clear_live_gpt").label == "Clear current live output"
    app.button("clear_live_gpt").click().run(timeout=_APP_TIMEOUT)
    assert "Live GPT-5.6 — completed" not in _visible_text(app)
    assert app.session_state["m05_live_success_scenarios"] == ("stable_symmetric",)
    assert app.button("live_gpt").disabled

    app.selectbox("scenario_selector").select("heavy_tail_particulate").run(timeout=_APP_TIMEOUT)
    assert "Live GPT-5.6 — completed" not in _visible_text(app)
    assert app.checkbox("live_gpt_ack").value is False
    assert app.button("live_gpt").disabled
    assert calls == [("stable_symmetric", "server-side-test-value")]

    app.selectbox("scenario_selector").select("stable_symmetric").run(timeout=_APP_TIMEOUT)
    assert app.button("live_gpt").disabled
    assert "already run for this scenario" in _visible_text(app)

    fresh = _app(live_enabled=True, deployment_credential="another-session-test-value")
    assert fresh.session_state["m05_live_success_scenarios"] == ()
    fresh.checkbox("live_gpt_ack").check().run(timeout=_APP_TIMEOUT)
    assert not fresh.button("live_gpt").disabled


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        (True, True),
        ("true", True),
        ("1", True),
        (" yes ", True),
        (False, False),
        ("false", False),
        ("enabled", False),
        (1, True),
        (None, False),
    ),
)
def test_live_enablement_uses_strict_true_values(value: object, expected: bool) -> None:
    from riec_guard.ui.app import _strict_true

    assert _strict_true(value) is expected
