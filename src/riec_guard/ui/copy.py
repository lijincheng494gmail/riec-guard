"""Central public-safe product copy for the Streamlit interface."""

from __future__ import annotations

from riec_guard.ui.models import UiGptCapability

PRODUCT_NAME = "RIEC Guard"
PRODUCT_TAGLINE = "Auditable decisions from conflicting evidence."
PRODUCT_SUPPORTING_LINE = (
    "Deterministic statistics decide. GPT-5.6 explains the evidence and audits the language."
)
PUBLIC_DEMO_DISCLAIMER = (
    "Public synthetic mechanism demo. Retrospective screening only—not a production setpoint, "
    "safety determination, compliance determination, or achieved-savings claim."
)
PIPELINE_RIBBON = "Profile → Contract → RIEC → Protocols → Action → GPT memo → Claim audit"
RECORDED_SOURCE_LABEL = "Recorded deterministic audit"
RECORDED_SOURCE_EXPLANATION = (
    "This result was generated through the accepted production-default pipeline with 200 "
    "whole-group bootstrap replicates and is bound to the committed synthetic dataset by SHA-256."
)
RECOMPUTED_SOURCE_LABEL = "Recomputed deterministic audit"
RECOMPUTED_SOURCE_EXPLANATION = (
    "This result was recomputed only after an explicit request through the accepted production "
    "pipeline with 200 whole-group bootstrap replicates."
)
LIVE_UNAVAILABLE_MESSAGE = (
    "Live GPT-5.6 is not configured on this deployment.\n\n"
    "The deterministic audit and offline fixture demonstration remain available."
)
GPT_DOES_NOT_DECIDE = "GPT-5.6 does not calculate the statistical result or choose the action."
PILOT_QUALIFICATION = (
    "Retrospective screening reference only. Controlled pilot and engineering review required; "
    "this is not a production setpoint."
)

ACTION_LABELS = {
    "invalid_contract": "Invalid contract",
    "insufficient_evidence": "Insufficient evidence",
    "no_actionable_headroom": "No actionable headroom",
    "diagnose_process_first": "Diagnose process first",
    "pilot_only_conservative": "Conservative pilot only",
    "pilot_range_supported": "Controlled pilot range supported",
}

ACTION_GUIDANCE = {
    "invalid_contract": "Correct and explicitly confirm the contract before analysis.",
    "insufficient_evidence": "Collect sufficient grouped evidence before considering an action.",
    "no_actionable_headroom": "No bounded pilot interval is supported by the accepted evidence.",
    "diagnose_process_first": (
        "Ordered stability is materially concerning. Diagnose the process before considering a "
        "pilot; no pilot interval is supported."
    ),
    "pilot_only_conservative": (
        "Protocol conflict requires the conservative retrospective screening reference."
    ),
    "pilot_range_supported": (
        "The accepted grouped evidence supports a bounded retrospective screening reference."
    ),
}

PROTOCOL_NAMES = {
    "D0": "Mean diagnostic",
    "H1": "Empirical strict-tail headroom",
    "H2": "Gaussian residual-tail headroom",
    "H3": "Student-t residual-tail headroom",
    "U1": "Whole-deployment-group bootstrap",
}

PROTOCOL_ROLES = {
    "D0": "Descriptive mean diagnostic only; it cannot independently support an action.",
    "H1": "Distribution-free strict empirical tail screen; ties and finite support remain visible.",
    "H2": "Gaussian residual-tail screen; interpretation depends on parametric diagnostics.",
    "H3": "Student-t residual-tail screen; no fallback is manufactured when the fit is ineligible.",
    "U1": (
        "Conditional lower bound from whole deployment-group resampling; candidate selection is "
        "held fixed."
    ),
}

GPT_CAPABILITIES = (
    UiGptCapability(
        title="Drafts an advisory column-role mapping",
        description=(
            "Suggests roles from the redacted profile; human confirmation remains required and "
            "analysis stays disabled."
        ),
    ),
    UiGptCapability(
        title="Explains deterministic results using cited evidence",
        description=(
            "Explains only allowlisted aggregate facts and cites the verified evidence chain."
        ),
    ),
    UiGptCapability(
        title="Audits the memo for unsupported or prohibited claims",
        description=(
            "Reviews memo language after deterministic blockers and cannot weaken those blockers."
        ),
    ),
)

METHOD_SUMMARY = (
    "Deterministic Python code owns profiling, the confirmed contract identity, grouped RIEC-L1 "
    "selection, H1/H2/H3/U1, G1/G2, protocol conflict, the six-state action, pilot bounds, and "
    "evidence provenance. GPT-5.6 receives sanitized aggregate facts only and is limited to "
    "advisory mapping, evidence-linked explanation, and claim review."
)

METHOD_LIMITATIONS = (
    "The committed datasets are public synthetic mechanisms, not calibrated process models.",
    "The analysis is retrospective screening and does not establish production safety, compliance, causality, or achieved savings.",
    "No raw rows, residual arrays, row predictions, local paths, prompts, or credentials enter the GPT workflow.",
    "Private and live industrial validation remains outside this public demonstration.",
)

__all__ = [
    "ACTION_GUIDANCE",
    "ACTION_LABELS",
    "GPT_CAPABILITIES",
    "GPT_DOES_NOT_DECIDE",
    "LIVE_UNAVAILABLE_MESSAGE",
    "METHOD_LIMITATIONS",
    "METHOD_SUMMARY",
    "PILOT_QUALIFICATION",
    "PIPELINE_RIBBON",
    "PRODUCT_NAME",
    "PRODUCT_SUPPORTING_LINE",
    "PRODUCT_TAGLINE",
    "PROTOCOL_NAMES",
    "PROTOCOL_ROLES",
    "PUBLIC_DEMO_DISCLAIMER",
    "RECORDED_SOURCE_EXPLANATION",
    "RECORDED_SOURCE_LABEL",
    "RECOMPUTED_SOURCE_EXPLANATION",
    "RECOMPUTED_SOURCE_LABEL",
]
