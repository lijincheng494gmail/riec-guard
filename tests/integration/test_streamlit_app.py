from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import pytest
from streamlit.testing.v1 import AppTest

from riec_guard.ui import backend
from riec_guard.ui.copy import LIVE_UNAVAILABLE_MESSAGE
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


def _app(*, live_enabled: bool = False, api_key: str | None = None) -> AppTest:
    app = AppTest.from_file(_APPLICATION_PATH, default_timeout=_APP_TIMEOUT)
    secrets: dict[str, object] = {"RIEC_GUARD_LIVE_GPT_ENABLED": live_enabled}
    if api_key is not None:
        secrets["OPENAI_API_KEY"] = api_key
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

    app = _app()
    visible = _visible_text(app)

    assert calls == {"recompute": 0, "fixture": 0, "live": 0}
    assert any(item.value == "RIEC Guard" for item in app.title)
    assert app.selectbox("scenario_selector").value == "stable_symmetric"
    assert [tab.label for tab in app.tabs] == ["Decision", "Evidence", "GPT-5.6", "Method"]
    assert "Recorded deterministic audit" in visible
    assert "Controlled pilot range supported" in visible
    assert "Auditable decisions from conflicting evidence." in visible
    assert "Deterministic statistics decide." in visible
    assert "Profile → Contract → RIEC → Protocols → Action → GPT memo → Claim audit" in visible
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
    assert automatic_calls == []

    app.selectbox("scenario_selector").select("batch_drift_change_point").run(timeout=_APP_TIMEOUT)
    assert len(app.exception) == 0
    drift_visible = _visible_text(app)
    assert "Diagnose process first" in drift_visible
    assert "No pilot interval is supported" in drift_visible
    assert "0.00–0.00" not in drift_visible
    assert automatic_calls == []


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
    app = _app(live_enabled=True, api_key="server-side-test-value")
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
    app = _app(live_enabled=True, api_key="server-side-test-value")
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

    fresh = _app(live_enabled=True, api_key="another-session-test-value")
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
