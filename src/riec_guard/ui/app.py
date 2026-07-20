"""Native Streamlit presentation for the accepted public RIEC Guard pipeline."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import cast

import streamlit as st
from streamlit.errors import StreamlitSecretNotFoundError

from riec_guard.errors import ErrorEnvelope
from riec_guard.ui import backend
from riec_guard.ui.copy import (
    ACTION_GUIDANCE,
    GPT_CAPABILITIES,
    GPT_DOES_NOT_DECIDE,
    LIVE_UNAVAILABLE_MESSAGE,
    METHOD_LIMITATIONS,
    METHOD_SUMMARY,
    PILOT_QUALIFICATION,
    PIPELINE_RIBBON,
    PRODUCT_NAME,
    PRODUCT_SUPPORTING_LINE,
    PRODUCT_TAGLINE,
    PUBLIC_DEMO_DISCLAIMER,
)
from riec_guard.ui.models import UiGptResult, UiScenarioBundle

_FIXTURE_RESULTS = "m05_fixture_results"
_LIVE_RESULTS = "m05_live_results"
_RECOMPUTED_RESULTS = "m05_recomputed_results"
_LIVE_SUCCESSES = "m05_live_success_scenarios"
_PREVIOUS_SCENARIO = "m05_previous_scenario"


def main() -> None:
    """Render one public-safe product page without automatic analysis or GPT calls."""

    st.set_page_config(page_title="RIEC Guard", page_icon="🛡️", layout="wide")
    _initialize_state()
    _render_header()

    try:
        definitions_result = backend.load_verified_scenario_definitions()
    except Exception:
        _render_fixed_error(
            "The recorded public demonstration could not be loaded safely.",
            "Use the accepted committed public assets and retry.",
        )
        return
    if isinstance(definitions_result, ErrorEnvelope):
        _render_error(definitions_result)
        return
    definitions = definitions_result
    display_names = {item.scenario_id: item.display_name for item in definitions}
    scenario_id = st.selectbox(
        "Public synthetic scenario",
        options=tuple(display_names),
        index=0,
        format_func=lambda value: display_names[str(value)],
        key="scenario_selector",
    )
    scenario_id = str(scenario_id)
    _handle_scenario_change(scenario_id)

    bundle = _selected_bundle(scenario_id)
    if bundle is None:
        return
    st.caption(f"{bundle.definition.mechanism_description} {bundle.definition.limitation}")

    if st.button("Recompute deterministic audit", key="recompute_audit"):
        try:
            with st.spinner("Running the accepted production-default audit…"):
                recomputed = backend.recompute_public_scenario(scenario_id)
        except Exception:
            recomputed = None
        if isinstance(recomputed, UiScenarioBundle):
            stored = dict(_bundle_results(_RECOMPUTED_RESULTS))
            stored[scenario_id] = recomputed
            st.session_state[_RECOMPUTED_RESULTS] = stored
            bundle = recomputed
            st.success("Deterministic recomputation completed and was verified against the record.")
        elif isinstance(recomputed, ErrorEnvelope):
            _render_error(recomputed)
        else:
            _render_fixed_error(
                "The deterministic audit could not be recomputed safely.",
                "Keep using the verified recorded audit or retry once.",
            )

    st.markdown(f"**{bundle.result_source}**")
    st.caption(bundle.source_explanation)

    decision_tab, evidence_tab, gpt_tab, method_tab = st.tabs(
        ["Decision", "Evidence", "GPT-5.6", "Method"]
    )
    with decision_tab:
        _render_decision(bundle)
    with evidence_tab:
        _render_evidence(bundle)
    with gpt_tab:
        _render_gpt(bundle)
    with method_tab:
        _render_method(bundle)


def _initialize_state() -> None:
    defaults: dict[str, object] = {
        _FIXTURE_RESULTS: {},
        _LIVE_RESULTS: {},
        _RECOMPUTED_RESULTS: {},
        _LIVE_SUCCESSES: (),
        _PREVIOUS_SCENARIO: None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def _render_header() -> None:
    st.title(PRODUCT_NAME)
    st.subheader(PRODUCT_TAGLINE)
    st.markdown(PRODUCT_SUPPORTING_LINE)
    st.info(PUBLIC_DEMO_DISCLAIMER)
    st.markdown(f"`{PIPELINE_RIBBON}`")


def _handle_scenario_change(scenario_id: str) -> None:
    previous = st.session_state[_PREVIOUS_SCENARIO]
    if previous is None:
        st.session_state[_PREVIOUS_SCENARIO] = scenario_id
        return
    if previous != scenario_id:
        st.session_state[_FIXTURE_RESULTS] = {}
        st.session_state[_LIVE_RESULTS] = {}
        if "live_gpt_ack" in st.session_state:
            st.session_state["live_gpt_ack"] = False
        st.session_state[_PREVIOUS_SCENARIO] = scenario_id


def _selected_bundle(scenario_id: str) -> UiScenarioBundle | None:
    recomputed = _bundle_results(_RECOMPUTED_RESULTS).get(scenario_id)
    if isinstance(recomputed, UiScenarioBundle):
        return recomputed
    try:
        result = backend.load_verified_recorded_scenario(scenario_id)
    except Exception:
        result = None
    if isinstance(result, UiScenarioBundle):
        return result
    if isinstance(result, ErrorEnvelope):
        _render_error(result)
    else:
        _render_fixed_error(
            "The recorded public demonstration could not be loaded safely.",
            "Use the accepted committed public assets and retry.",
        )
    return None


def _render_decision(bundle: UiScenarioBundle) -> None:
    decision = bundle.decision
    st.header(decision.action_label)
    st.markdown(f"**Action state:** `{decision.action_state}`")
    st.caption(f"Decision unit: {decision.unit}")
    st.caption(f"Deterministic-result source: {bundle.result_source}")
    st.write(ACTION_GUIDANCE[decision.action_state])
    metrics = st.columns(4)
    metrics[0].metric("Rows", f"{bundle.row_count:,}")
    metrics[1].metric("Deployment groups", bundle.deployment_group_count)
    metrics[2].metric("Products", bundle.product_count)
    metrics[3].metric("RIEC winner", bundle.riec_winner)

    gate_by_id = {gate.gate_id: gate for gate in bundle.gates}
    detail_columns = st.columns(3)
    detail_columns[0].metric("G1 ordered stability", gate_by_id["G1"].status)
    detail_columns[1].metric("G2 evidence", gate_by_id["G2"].status)
    detail_columns[2].metric(
        "Protocol conflict", "material" if decision.protocol_conflict else "none"
    )

    st.markdown(f"**Decisive reason:** `{decision.decisive_reason}`")
    if decision.has_pilot_interval:
        st.metric(
            "Retrospective screening reference",
            f"{decision.pilot_min:.2f}–{decision.pilot_max:.2f} {decision.unit}",
        )
        st.warning(PILOT_QUALIFICATION)
    else:
        st.info("No pilot interval is supported for this action state.")
    st.write(decision.conflict_summary)
    with st.expander("Decision limitations"):
        for limitation in bundle.limitations:
            st.write(f"- {limitation}")

    gpt_result = _current_gpt_result(bundle.definition.scenario_id)
    try:
        packet = backend.build_download_packet(bundle, gpt_result=gpt_result)
    except Exception:
        packet = None
    if isinstance(packet, ErrorEnvelope):
        _render_error(packet)
    elif packet is not None:
        st.download_button(
            "Download sanitized decision packet",
            data=packet.content,
            file_name=packet.filename,
            mime=packet.media_type,
            key="decision_download",
        )
        st.caption(f"Download SHA-256: `{packet.content_sha256}`")
    else:
        _render_fixed_error(
            "The sanitized decision download is temporarily unavailable.",
            "Reload the selected public scenario and retry.",
        )


def _render_evidence(bundle: UiScenarioBundle) -> None:
    st.header("Protocol evidence")
    if bundle.result_source.startswith("Recorded"):
        st.caption(
            "D0 is not included in the sealed recorded display asset; it appears only after an "
            "explicit deterministic recomputation."
        )
    st.table(
        [
            {
                "Protocol": row.protocol_id,
                "Method": row.name,
                "Status": row.status,
                "Estimate": _value(row.value, row.unit),
                "Lower bound": _value(row.lower_bound, row.unit),
                "Role / limitation": row.role_limitation,
            }
            for row in bundle.protocols
        ]
    )
    chart_rows = [
        row
        for row in bundle.protocols
        if row.protocol_id in {"H1", "H2", "H3"} and row.value is not None
    ]
    if len(chart_rows) >= 2:
        st.bar_chart(
            {
                "protocol": [row.protocol_id for row in chart_rows],
                "headroom_mL": [row.value for row in chart_rows],
            },
            x="protocol",
            y="headroom_mL",
            x_label="Protocol",
            y_label="Headroom (mL)",
        )

    st.subheader("Conflict, gates, and uncertainty")
    st.write(
        f"Protocol spread: {_value(bundle.decision.protocol_spread, bundle.decision.unit)}; "
        f"tolerance: {bundle.protocol_spread_tolerance:.2f} {bundle.decision.unit}."
    )
    st.write(bundle.decision.conflict_summary)
    for gate in bundle.gates:
        st.markdown(f"**{gate.gate_id} — {gate.status}:** {gate.detail}")
    st.write(
        "U1 whole-group bootstrap: "
        f"{bundle.bootstrap_successful}/{bundle.bootstrap_requested} successful, "
        f"{bundle.bootstrap_failed} failed; seed {bundle.bootstrap_seed}."
    )

    st.subheader("Grouped RIEC-L1 selection")
    st.write(f"Winner: `{bundle.riec_winner}`")
    st.write(f"Runner-up: `{bundle.riec_runner_up or 'none'}`")
    st.write(f"Near tie: `{str(bundle.riec_near_tie).lower()}`")
    st.write(f"Equivalence set: `{', '.join(bundle.equivalence_set)}`")

    st.subheader("Aggregate evidence chain")
    st.caption("Short identifiers are shown here; expand for the full IDs and hashes.")
    for node in bundle.evidence_nodes:
        short = f"{node.evidence_id[:18]}…{node.evidence_id[-4:]}"
        st.write(f"{node.component}: `{short}`")
    with st.expander("Full evidence identities"):
        for node in bundle.evidence_nodes:
            st.markdown(f"**{node.component}**")
            st.code(
                f"evidence_id: {node.evidence_id}\n"
                f"content_sha256: {node.content_sha256}\n"
                f"parents: {', '.join(node.parent_evidence_ids) or 'none'}"
            )


def _render_gpt(bundle: UiScenarioBundle) -> None:
    scenario_id = bundle.definition.scenario_id
    st.header("GPT-5.6 interpretation")
    capability_columns = st.columns(3)
    for column, capability in zip(capability_columns, GPT_CAPABILITIES, strict=True):
        column.markdown(f"**{capability.title}**")
        column.write(capability.description)
    st.warning(GPT_DOES_NOT_DECIDE)

    if st.button("Generate offline fixture memo", key="fixture_gpt"):
        try:
            with st.spinner("Running the deterministic non-live GPT fixture…"):
                fixture = backend.run_fixture_gpt_workflow(scenario_id)
        except Exception:
            fixture = None
        if isinstance(fixture, UiGptResult):
            stored = dict(_gpt_results(_FIXTURE_RESULTS))
            stored[scenario_id] = fixture
            st.session_state[_FIXTURE_RESULTS] = stored
            st.rerun()
        elif isinstance(fixture, ErrorEnvelope):
            _render_error(fixture)
        else:
            _render_fixed_error(
                "Narrative assistance could not be completed safely.",
                "The deterministic audit remains available; retry fixture mode later.",
            )

    enabled, api_key = _live_configuration()
    successful = scenario_id in _live_successes()
    if not enabled or api_key is None:
        st.info(LIVE_UNAVAILABLE_MESSAGE)
    else:
        acknowledged = st.checkbox(
            "I understand this will make a bounded live API request.",
            key="live_gpt_ack",
        )
        clicked = st.button(
            "Generate with live GPT-5.6",
            key="live_gpt",
            disabled=not acknowledged or successful,
        )
        if successful:
            st.info("One successful live GPT-5.6 workflow has already run for this scenario.")
        if clicked:
            # Disabled widgets can still be forced by test clients, so revalidate every
            # server-side boundary at the event itself.
            current_enabled, current_key = _live_configuration()
            if (
                current_enabled
                and current_key is not None
                and acknowledged
                and scenario_id not in _live_successes()
            ):
                try:
                    with st.spinner("Running one bounded live GPT-5.6 workflow…"):
                        live = backend.run_live_gpt_workflow(
                            scenario_id,
                            deployment_credential=current_key,
                        )
                except Exception:
                    live = None
                if isinstance(live, UiGptResult):
                    stored_live = dict(_gpt_results(_LIVE_RESULTS))
                    stored_live[scenario_id] = live
                    st.session_state[_LIVE_RESULTS] = stored_live
                    if live.status == "completed":
                        st.session_state[_LIVE_SUCCESSES] = (*_live_successes(), scenario_id)
                    st.rerun()
                elif isinstance(live, ErrorEnvelope):
                    _render_error(live)
                else:
                    _render_fixed_error(
                        "Live narrative assistance could not be completed safely.",
                        "The deterministic audit remains available; review deployment access.",
                    )
            else:
                st.warning(
                    "Live GPT-5.6 requires server-side enablement, a deployment secret, explicit "
                    "confirmation, and an unused scenario allowance."
                )

    live_result = _gpt_results(_LIVE_RESULTS).get(scenario_id)
    if isinstance(live_result, UiGptResult) and st.button(
        "Clear current live output", key="clear_live_gpt"
    ):
        stored_live = dict(_gpt_results(_LIVE_RESULTS))
        stored_live.pop(scenario_id, None)
        st.session_state[_LIVE_RESULTS] = stored_live
    result = _current_gpt_result(scenario_id)
    if result is not None:
        _render_gpt_result(result)


def _render_gpt_result(result: UiGptResult) -> None:
    st.subheader(f"{result.mode_label} — {result.status}")
    st.write(result.user_message)
    st.caption(
        f"Context source: {result.context_source}; Model: {result.requested_model}; "
        f"prompt versions: {', '.join(result.prompt_versions)}"
    )
    st.caption(f"Workflow SHA-256: `{result.workflow_sha256}`")

    if result.contract_suggestions:
        st.markdown("**Advisory contract-role suggestions**")
        st.table(
            [
                {
                    "Role": item.role,
                    "Column": item.column or "unresolved",
                    "Confidence": f"{item.confidence:.2f}",
                    "Reason": item.reason,
                }
                for item in result.contract_suggestions
            ]
        )
        st.caption(
            "Human confirmation required: "
            f"{str(result.requires_human_confirmation).lower()}; analysis permitted by "
            f"suggestion: {str(result.analysis_permitted).lower()}."
        )

    if result.memo_title is not None:
        st.markdown(f"### {result.memo_title}")
        st.markdown(f"**Decision snapshot:** {result.decision_snapshot}")
        st.markdown(f"**What the evidence shows:** {result.evidence_summary}")
        st.markdown(f"**Why protocol choice matters:** {result.protocol_explanation}")
        st.markdown(f"**Recommended next step:** {result.recommended_next_step}")
        st.markdown("**Evidence-linked findings**")
        st.table(
            [
                {
                    "Finding": item.finding_id,
                    "Importance": item.importance,
                    "Statement": item.statement,
                    "Evidence": ", ".join(item.evidence_ids),
                    "Facts": ", ".join(item.fact_keys),
                }
                for item in result.findings
            ]
        )
        with st.expander("Memo limitations"):
            for limitation in result.memo_limitations:
                st.write(f"- {limitation}")

    if result.claim_audit_status is not None:
        st.markdown(
            "**Claim audit:** "
            f"{result.claim_audit_status} (deterministic validation: "
            f"{result.deterministic_validation_status})"
        )
        st.table(
            [
                {
                    "Claim": item.claim_id,
                    "Verdict": item.verdict,
                    "Reason": item.reason,
                    "Evidence": ", ".join(item.evidence_ids),
                    "Revision": item.suggested_revision or "—",
                }
                for item in result.claim_reviews
            ]
        )
    with st.expander("Bounded GPT call metadata"):
        st.table(
            [
                {
                    "Task": item.task,
                    "Status": item.status,
                    "Mode": item.execution_mode,
                    "Prompt version": item.prompt_version,
                    "Requested model": item.requested_model,
                    "Returned model": item.returned_model,
                    "Response ID": item.response_id,
                    "Attempts": item.attempt_count,
                    "Input tokens": item.input_tokens,
                    "Output tokens": item.output_tokens,
                    "Total tokens": item.total_tokens,
                    "Input SHA-256": item.input_sha256,
                    "Output SHA-256": item.output_sha256,
                }
                for item in result.calls
            ]
        )
        st.caption("Prompt text and hidden reasoning are never displayed or stored here.")


def _render_method(bundle: UiScenarioBundle) -> None:
    st.header("Method and product boundary")
    st.markdown(
        "`Public synthetic data → Safe profile → Human-confirmed contract → Grouped RIEC-L1 → "
        "Tail protocols and uncertainty → Stability and evidence gates → Six-state action engine "
        "→ GPT-5.6 explanation → Claim audit`"
    )
    st.write(METHOD_SUMMARY)
    st.markdown("**Deterministic result modes**")
    st.write(
        "Recorded mode verifies committed catalog, result, CSV, policy, and evidence identities "
        "without statistical recomputation. Recomputed mode runs only after the explicit button."
    )
    st.markdown("**Current result identity**")
    st.code(
        f"scenario: {bundle.definition.scenario_id}\n"
        f"source: {bundle.result_source}\n"
        f"dataset_sha256: {bundle.dataset_sha256}\n"
        f"contract_id: {bundle.contract_id}"
    )
    st.markdown("**Limitations**")
    for limitation in METHOD_LIMITATIONS:
        st.write(f"- {limitation}")


def _live_configuration() -> tuple[bool, str | None]:
    enabled_value = _server_setting("RIEC_GUARD_LIVE_GPT_ENABLED")
    key_value = _server_setting("OPENAI_API_KEY")
    enabled = _strict_true(enabled_value)
    deployment_credential = (
        key_value if isinstance(key_value, str) and bool(key_value.strip()) else None
    )
    return enabled, deployment_credential


def _server_setting(name: str) -> object | None:
    environment_value = os.environ.get(name)
    if environment_value is not None:
        return environment_value
    try:
        return st.secrets[name]
    except (StreamlitSecretNotFoundError, KeyError):
        return None


def _strict_true(value: object) -> bool:
    if value is True:
        return True
    if isinstance(value, int) and not isinstance(value, bool) and value == 1:
        return True
    return isinstance(value, str) and value.strip().casefold() in {"true", "1", "yes"}


def _bundle_results(key: str) -> Mapping[str, object]:
    value = st.session_state[key]
    return cast(Mapping[str, object], value) if isinstance(value, Mapping) else {}


def _gpt_results(key: str) -> Mapping[str, object]:
    value = st.session_state[key]
    return cast(Mapping[str, object], value) if isinstance(value, Mapping) else {}


def _live_successes() -> tuple[str, ...]:
    value = st.session_state[_LIVE_SUCCESSES]
    if isinstance(value, tuple) and all(isinstance(item, str) for item in value):
        return value
    return ()


def _current_gpt_result(scenario_id: str) -> UiGptResult | None:
    live = _gpt_results(_LIVE_RESULTS).get(scenario_id)
    if isinstance(live, UiGptResult):
        return live
    fixture = _gpt_results(_FIXTURE_RESULTS).get(scenario_id)
    return fixture if isinstance(fixture, UiGptResult) else None


def _value(value: float | None, unit: str | None) -> str:
    if value is None:
        return "not available"
    return f"{value:.2f} {unit}" if unit else f"{value:.2f}"


def _render_error(error: ErrorEnvelope) -> None:
    st.error(error.message)
    if error.user_action:
        st.caption(error.user_action)


def _render_fixed_error(message: str, user_action: str) -> None:
    st.error(message)
    st.caption(user_action)


__all__ = ["main"]
