# RIEC Guard

**Auditable decisions from conflicting evidence.**

Deterministic statistics decide. GPT-5.6 explains the evidence and audits the language.

## Product summary

Operational datasets can support conflicting analytical protocols, leaving teams without a
defensible next action. RIEC Guard turns that disagreement into a bounded, auditable decision.
It profiles a public synthetic source, binds a confirmed data contract, selects from a fixed
grouped RIEC-L1 candidate library, evaluates empirical, Gaussian, and Student-t tail headroom,
adds whole-group uncertainty and stability/evidence gates, and maps the result through a
six-state action engine. Deterministic code owns every number, gate, action, and pilot range.
GPT-5.6 sits downstream: it proposes advisory column roles, drafts an evidence-linked decision
memo, and performs a semantic claim audit through structured Responses API output. Raw rows are
not sent to GPT. Three committed synthetic mechanisms demonstrate protocol agreement,
heavy-tail conflict, and ordered process instability without exposing industrial data.

## Working demo

The repository-root entry point is `streamlit_app.py`. Fixture mode works without an API key;
live GPT mode is optional and requires server-side configuration plus an explicit user action.
The deployment URL will be supplied through the submission form after deployment—this repository
does not claim that an external deployment already exists.

The default app loads a verified recorded result without statistical recomputation. Select
**Recompute deterministic audit** only when you want to run the accepted production-default
pipeline, including 200 whole-deployment-group bootstrap replicates.

## Three-scenario walkthrough

| Scenario | Recorded action | Retrospective screening reference |
|---|---|---|
| `stable_symmetric` | `pilot_range_supported` | 0.15–0.40 mL |
| `heavy_tail_particulate` | `pilot_only_conservative` | 0.05–0.14 mL |
| `batch_drift_change_point` | `diagnose_process_first` | No pilot interval |

The stable mechanism shows protocol agreement. The heavy-tail mechanism makes the empirical
result more conservative than the parametric results, so the action engine exposes the conflict.
The drift mechanism raises an ordered-stability warning and directs the user to diagnose the
process before considering a pilot.

## Architecture

```text
Public synthetic data
  → Safe profile
  → Confirmed contract
  → Grouped RIEC-L1
  → H1 / H2 / H3 / U1
  → G1 / G2
  → Six-state action engine
  → GPT-5.6 memo
  → Claim audit
```

**Deterministic code owns every numerical result and action.** The evidence path is aggregate and
run-bound: RIEC evidence precedes protocol evidence, which precedes the action evidence consumed
by the bounded narrative layer. See [Architecture](docs/ARCHITECTURE.md) for details.

## GPT-5.6 role

GPT-5.6 is an auditable interpretation layer, not the analytical decision-maker. It provides:

- advisory column-role suggestions that still require human confirmation;
- an evidence-linked decision memo built only from allowlisted aggregate facts;
- a semantic claim audit with deterministic precedence;
- strict structured output through the OpenAI Responses API.

Raw rows are not sent to GPT. GPT cannot alter the fitted statistics, protocol results, evidence
gates, action state, or pilot range. Fixture mode exercises the complete structured workflow
without an API request.

## Codex collaboration

Codex implemented and tested the public product under human-directed specifications. Its work
included repository hardening, deterministic grouped analysis, Fill protocols, focused tests,
specification enforcement, the bounded GPT interface, the Streamlit product, and release checks.
It also stopped on real blockers instead of weakening the method: Codex correctly caught that the
original 192-row benchmark could not satisfy the frozen 1% tail-evidence threshold. The human
retained that threshold and expanded each synthetic world to 1,056 rows. Focused macro tests
replaced repeated certification-style full runs, with the final full suite reserved for release.

Codex did not author the underlying research method. Human direction retained statistical
ownership in deterministic code, preserved evidence thresholds, and kept GPT advisory and
auditable.

## Build Week provenance

The RIEC-L1 research concept and its peer-reviewed methodological lineage predate Build Week. No
claim is made that this product itself is peer-reviewed.

Build Week work created or meaningfully extended the secure public-source workflow, grouped RIEC
engine, Fill protocols, uncertainty and evidence gates, six-state action engine, three synthetic
demo worlds, GPT-5.6 workflow, Streamlit application, and release/testing infrastructure. The
dated history and human/agent boundary are recorded in
[Build Week provenance](docs/BUILD_WEEK_PROVENANCE.md) using actual Git commits. No publication
URL or inferred citation metadata is asserted here.

## Quick start

Prerequisites are `uv`, Git, and a platform capable of running managed Python 3.12. The repository
pins Python 3.12.13 and all direct/transitive packages in `requirements.lock`.

```bash
make install
.venv/bin/python scripts/build_demo_assets.py --check
.venv/bin/python -m streamlit run streamlit_app.py
```

Run these commands from the repository root after obtaining the human-supplied repository
location. Benchmark regeneration is not required for normal use.

## Live GPT setup

There is no browser API-key field. Configure the key and enable flag only in the server
environment. The app still requires an in-app confirmation and an explicit
**Generate with live GPT-5.6** action.

```bash
export OPENAI_API_KEY="<deployment-secret>"
export RIEC_GUARD_LIVE_GPT_ENABLED="true"
.venv/bin/python -m streamlit run streamlit_app.py
```

The exact bounded CLI live-smoke checkpoint is for a manually authorized human run only:

```bash
read -s OPENAI_API_KEY
export OPENAI_API_KEY
export RIEC_GUARD_LIVE_GPT_ENABLED=true

.venv/bin/python scripts/run_gpt_workflow.py \
  --scenario stable_symmetric \
  --live

unset OPENAI_API_KEY
unset RIEC_GUARD_LIVE_GPT_ENABLED
```

## Testing

All commands run from the repository root after `make install`:

```bash
# Deterministic, no-key GPT workflow
.venv/bin/python scripts/run_gpt_workflow.py \
  --scenario stable_symmetric \
  --fixture

# Recorded synthetic-asset verification (no analysis)
.venv/bin/python scripts/build_demo_assets.py --check

# Streamlit component and localhost health checks
.venv/bin/python scripts/check_streamlit_app.py --app-test
.venv/bin/python scripts/check_streamlit_app.py --server-smoke

# Complete repository suite
make test
```

See the [testing instructions](submission/TESTING_INSTRUCTIONS.md) and
[five-minute judging guide](docs/JUDGING_GUIDE.md).

## Privacy and limitations

- The committed demonstration data are public and synthetic; they are not calibrated process
  models.
- Raw rows, CSV contents, residual arrays, row predictions, local paths, prompts, and credentials
  are not sent to GPT.
- Results are retrospective screening aids, not production setpoints.
- The product does not make a safety or compliance determination.
- It does not claim achieved savings, causality, or universal validation.
- Private adapters and industrial validation are outside the public demonstration.

## Repository map

```text
streamlit_app.py                 Public application entry point
src/riec_guard/                  Deterministic, GPT, evidence, and UI services
data/public_synthetic/           Three committed synthetic scenario CSVs
demo_assets/                     Recorded catalog and benchmark summary
scripts/                         Asset, GPT, Streamlit, and release checks
tests/                           Unit, integration, security, golden, and release tests
docs/                            Architecture, provenance, deployment, and judging guides
submission/                      Draft submission, video, testing, and release materials
```

## License

RIEC Guard is available under the [MIT License](LICENSE), copyright (c) 2026 RIEC Guard
contributors. Third-party dependencies remain under their respective licenses.
