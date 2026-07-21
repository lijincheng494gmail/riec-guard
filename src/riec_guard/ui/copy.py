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
PUBLIC_DEMO_GUIDE = """
**Quick walkthrough**

1. Select one of the three public synthetic scenarios.
2. Read the Decision tab for the action and any retrospective screening range.
3. Open Evidence to compare H1, H2, H3, U1, G1, and G2.
4. Open GPT-5.6 and select `Generate offline fixture memo`.
5. Review the evidence-linked memo and claim audit.
6. Download the sanitized decision packet when useful.

**Expected scenario behavior**

- Stable symmetric process: controlled pilot range supported; 0.15–0.40 mL.
- Heavy-tail particulate variation: conservative pilot only; 0.05–0.14 mL; material protocol conflict.
- Batch drift and change point: diagnose process first; no pilot interval.

**Deterministic/GPT boundary**

- Deterministic Python owns every numerical result and action.
- GPT-5.6 explains sanitized aggregate evidence and audits language.
- Raw rows are not sent to GPT.
- The offline fixture makes no API request.

**Recorded-result explanation**

The public app defaults to the committed recorded audit. It was generated using 200 whole-group
bootstrap replicates and is bound to the committed synthetic dataset by SHA-256. This is a
retrospective screening demonstration, not a production setpoint, safety determination, compliance
determination, or achieved-savings claim.
""".strip()
PUBLIC_RECORDED_MODE_CAPTION = (
    "This public demo uses the verified recorded audit. Deterministic recomputation is available "
    "only in explicitly enabled development environments."
)
RECOMPUTE_UNAVAILABLE_MESSAGE = (
    "Live recomputation is unavailable in this environment. The verified recorded audit remains "
    "active."
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
    "PUBLIC_DEMO_GUIDE",
    "PUBLIC_DEMO_DISCLAIMER",
    "PUBLIC_RECORDED_MODE_CAPTION",
    "RECORDED_SOURCE_EXPLANATION",
    "RECORDED_SOURCE_LABEL",
    "RECOMPUTE_UNAVAILABLE_MESSAGE",
    "RECOMPUTED_SOURCE_EXPLANATION",
    "RECOMPUTED_SOURCE_LABEL",
]
