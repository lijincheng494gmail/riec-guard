# Five-minute judging guide

RIEC Guard is a Work & Productivity project that turns conflicting analytical evidence into a
deterministic, auditable next action. The fastest review uses the externally supplied Streamlit
URL once deployment is complete. No URL is embedded here because deployment remains a human
checkpoint.

Judges do not need to regenerate benchmark assets. The app's default recorded mode verifies the
committed synthetic data, summary, evidence identities, and hashes without rerunning analysis.

## Fastest deployed path

1. Open the working demo URL supplied in the submission form after deployment.
2. Confirm the ownership ribbon: deterministic statistics decide; GPT-5.6 explains and audits.
3. Follow the timed walkthrough below, using the scenario selector at the top of the app.

## Local no-key path

Use Python 3.12 (the repository pins 3.12.13) and Streamlit 1.59.2:

```bash
make install
.venv/bin/python scripts/build_demo_assets.py --check
.venv/bin/python -m streamlit run streamlit_app.py
```

Open the local address printed by Streamlit. No API key is required. The exact repository-root
entry point is `streamlit_app.py` on branch `build-week-2026`.

## Timed walkthrough

### 0:00–0:45 — Product and deterministic boundary

- Start on **Stable symmetric process**, the default selection.
- Read the action in the **Decision** tab: `pilot_range_supported`.
- Confirm the retrospective screening reference is **0.15–0.40 mL**.
- Note that the source label is **Recorded deterministic audit**. Ordinary page load has not
  recomputed statistics.

### 0:45–1:40 — Stable evidence

- Open **Evidence**.
- Inspect H1/H2/H3/U1 and the G1/G2 gate summaries.
- Confirm the RIEC → protocol → action evidence lineage.
- Return to **Decision**. The interval is a screening reference, not a production setpoint.

### 1:40–2:35 — Heavy-tail conflict

- Select **Heavy-tail particulate variation**.
- Confirm `pilot_only_conservative` and the conservative **0.05–0.14 mL** range.
- Observe that protocol conflict is visible rather than averaged away: the empirical strict-tail
  result is more conservative than the parametric results.

### 2:35–3:25 — Drift blocks a pilot

- Select **Batch drift and change point**.
- Confirm `diagnose_process_first`.
- Confirm that no pilot interval is shown and that G1 has a material ordered-stability warning.
- This demonstrates that adequate row counts alone do not override process instability.

### 3:25–4:25 — GPT-5.6 workflow

- Return to **Stable symmetric process**, open **GPT-5.6**, and select
  **Generate offline fixture memo**.
- Inspect the advisory role mapping, evidence-linked memo, response metadata, and claim-audit
  result. This deterministic fixture makes no API request.
- GPT receives aggregate allowlisted facts, not raw rows, and cannot alter the action or interval.

If a host has been deliberately configured with `OPENAI_API_KEY` and
`RIEC_GUARD_LIVE_GPT_ENABLED=true`, the same tab presents an acknowledgement followed by
**Generate with live GPT-5.6**. Live mode is optional; a missing live configuration does not block
the deterministic audit or fixture demonstration.

### 4:25–5:00 — Download and limitations

- In **Decision**, select **Download sanitized decision packet**.
- The deterministic JSON is generated in memory and excludes raw rows, CSV contents, paths,
  credentials, prompts, and hidden reasoning.
- Open **Method** for the deterministic/GPT ownership summary and the safety boundary.

## Expected outcomes at a glance

| Selector option | Canonical result | Interval |
|---|---|---|
| Stable symmetric process | `pilot_range_supported` | 0.15–0.40 mL |
| Heavy-tail particulate variation | `pilot_only_conservative` | 0.05–0.14 mL |
| Batch drift and change point | `diagnose_process_first` | None |

## Safety boundary

- All three datasets are public synthetic mechanisms, not calibrated industrial processes.
- Deterministic code owns every number and action; GPT-5.6 is explanatory and auditable.
- Raw rows are not sent to GPT.
- Results are retrospective screening aids, not production setpoints.
- The demo does not establish safety, compliance, causality, achieved savings, or universal
  validation.
- Private adapters and industrial validation remain outside this public product.
