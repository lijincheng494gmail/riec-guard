#!/usr/bin/env python3
"""Run bounded, network-free checks for the public Streamlit application."""

from __future__ import annotations

import argparse
import http.client
import importlib.util
import os
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_APPLICATION_PATH = _REPOSITORY_ROOT / "streamlit_app.py"
_LIVE_ENVIRONMENT_NAMES = ("OPENAI_API_KEY", "RIEC_GUARD_LIVE_GPT_ENABLED")
_APP_TEST_TIMEOUT_SECONDS = 30.0
_SERVER_START_TIMEOUT_SECONDS = 30.0
_SERVER_STOP_TIMEOUT_SECONDS = 5.0
_SERVER_POLL_SECONDS = 0.2
_SERVER_PORT = 18501
_HEALTH_PATH = "/_stcore/health"


class CheckFailure(RuntimeError):
    """A public-safe failure raised by a bounded application check."""


@contextmanager
def _live_environment_scrubbed() -> Iterator[None]:
    saved = {name: os.environ.get(name) for name in _LIVE_ENVIRONMENT_NAMES}
    for name in _LIVE_ENVIRONMENT_NAMES:
        os.environ.pop(name, None)
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def _normalized(value: object) -> str:
    return " ".join(str(value).split())


def _visible_text(app_test: Any) -> str:
    fragments: list[str] = []
    element_groups = (
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
    )
    for group_name in element_groups:
        for element in getattr(app_test, group_name, ()):  # AppTest versions vary slightly.
            for attribute in ("label", "value"):
                value = getattr(element, attribute, None)
                if value is not None:
                    fragments.append(str(value))
    return _normalized("\n".join(fragments))


def _find_widget(widgets: Iterable[Any], key: str) -> Any | None:
    return next((widget for widget in widgets if getattr(widget, "key", None) == key), None)


def _run_app_test() -> None:
    try:
        from streamlit.testing.v1 import AppTest
    except (ImportError, ModuleNotFoundError):
        _run_reduced_import_check()
        print("app-test: PASS (reduced import/view-model mode; AppTest unavailable)")
        return

    with _live_environment_scrubbed():
        app = AppTest.from_file(
            _APPLICATION_PATH,
            default_timeout=_APP_TEST_TIMEOUT_SECONDS,
        )
        # A nonempty programmatic mapping prevents any developer-local secrets file
        # from participating in this intentionally live-disabled check.
        app.secrets = {"RIEC_GUARD_LIVE_GPT_ENABLED": False}
        app.run(timeout=_APP_TEST_TIMEOUT_SECONDS)

    _require(len(app.exception) == 0, "the application raised an uncaught exception")
    _require(any(item.value == "RIEC Guard" for item in app.title), "the product title is absent")

    selector = _find_widget(app.selectbox, "scenario_selector")
    if selector is None:
        raise CheckFailure("the scenario selector is absent")
    selected_value = getattr(getattr(selector, "value", None), "value", selector.value)
    _require(
        selected_value in {"stable_symmetric", "Stable symmetric process"},
        "the default scenario is not stable symmetric",
    )

    tab_labels = {tab.label for tab in app.tabs}
    _require(
        {"Decision", "Evidence", "GPT-5.6", "Method"}.issubset(tab_labels),
        "one or more required product tabs are absent",
    )

    fixture_button = _find_widget(app.button, "fixture_gpt")
    if fixture_button is None:
        raise CheckFailure("the fixture narrative control is absent")
    _require(
        fixture_button.label == "Generate offline fixture memo" and not fixture_button.disabled,
        "the fixture narrative control is not available",
    )

    live_button = _find_widget(app.button, "live_gpt")
    _require(
        live_button is None or live_button.disabled,
        "live GPT is enabled without server-side configuration",
    )

    visible = _visible_text(app)
    required_text = (
        "Recorded deterministic audit",
        "Controlled pilot range supported",
        "Live GPT-5.6 is not configured on this deployment. "
        "The deterministic audit and offline fixture demonstration remain available.",
    )
    for text in required_text:
        _require(_normalized(text) in visible, "a required default recorded-mode result is absent")

    print("app-test: PASS (AppTest; stable recorded mode; fixture available; live disabled)")


def _run_reduced_import_check() -> None:
    _require(_APPLICATION_PATH.is_file(), "the root application entry point is absent")
    module_name = "_riec_guard_streamlit_entry_check"
    spec = importlib.util.spec_from_file_location(module_name, _APPLICATION_PATH)
    if spec is None or spec.loader is None:
        raise CheckFailure("the entry point cannot be imported")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _require(callable(getattr(module, "main", None)), "the entry point does not expose main")

    from riec_guard.errors import ErrorEnvelope
    from riec_guard.ui.backend import load_verified_recorded_scenario
    from riec_guard.ui.models import UiScenarioBundle

    bundle = load_verified_recorded_scenario("stable_symmetric")
    _require(
        not isinstance(bundle, ErrorEnvelope),
        "the stable recorded bundle failed verification",
    )
    _require(isinstance(bundle, UiScenarioBundle), "the loader did not return a UI scenario bundle")


def _assert_fixed_port_available() -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.settimeout(1.0)
        probe.bind(("127.0.0.1", _SERVER_PORT))
    except OSError as exc:
        raise CheckFailure("the fixed localhost smoke port is unavailable") from exc
    finally:
        probe.close()


def _health_endpoint_is_ready(timeout_seconds: float) -> bool:
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        _SERVER_PORT,
        timeout=max(0.05, min(timeout_seconds, 1.0)),
    )
    try:
        connection.request("GET", _HEALTH_PATH)
        response = connection.getresponse()
        body = response.read(64).strip().lower()
        return response.status == 200 and body == b"ok"
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=_SERVER_STOP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=_SERVER_STOP_TIMEOUT_SECONDS)


def _run_server_smoke() -> None:
    _require(_APPLICATION_PATH.is_file(), "the root application entry point is absent")
    _assert_fixed_port_available()

    environment = os.environ.copy()
    for name in _LIVE_ENVIRONMENT_NAMES:
        environment.pop(name, None)
    environment["STREAMLIT_BROWSER_GATHER_USAGE_STATS"] = "false"

    with tempfile.TemporaryDirectory(prefix="riec-guard-streamlit-smoke-") as temporary:
        secrets_file = Path(temporary) / "secrets.toml"
        secrets_file.write_text("RIEC_GUARD_LIVE_GPT_ENABLED = false\n", encoding="utf-8")
        command = (
            sys.executable,
            "-m",
            "streamlit",
            "run",
            str(_APPLICATION_PATH),
            "--server.headless=true",
            "--server.address=127.0.0.1",
            f"--server.port={_SERVER_PORT}",
            "--server.enableCORS=true",
            "--server.enableXsrfProtection=true",
            "--server.fileWatcherType=none",
            "--browser.gatherUsageStats=false",
            "--secrets.files",
            str(secrets_file),
        )
        process = subprocess.Popen(
            command,
            cwd=_REPOSITORY_ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
        )
        try:
            deadline = time.monotonic() + _SERVER_START_TIMEOUT_SECONDS
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise CheckFailure(
                        "the localhost Streamlit server exited before becoming healthy"
                    )
                remaining = deadline - time.monotonic()
                if _health_endpoint_is_ready(remaining):
                    print("server-smoke: PASS (localhost health endpoint returned HTTP 200)")
                    return
                time.sleep(_SERVER_POLL_SECONDS)
            raise CheckFailure("the localhost Streamlit health check reached its hard timeout")
        finally:
            _stop_process(process)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--app-test", action="store_true", help="run a network-free AppTest")
    modes.add_argument(
        "--server-smoke",
        action="store_true",
        help="run one bounded localhost health check",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.app_test:
            _run_app_test()
        else:
            _run_server_smoke()
    except CheckFailure as exc:
        print(f"streamlit-check: FAIL ({exc})", file=sys.stderr)
        return 1
    except Exception:
        print("streamlit-check: FAIL (unexpected internal check failure)", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
