# Devpost Submission Draft

## Project name

RIEC Guard

## Track

Work & Productivity

## Tagline

Auditable decisions from conflicting evidence.

## One-sentence pitch

RIEC Guard turns conflicting analytical protocols into deterministic, evidence-linked action
states, then uses bounded GPT-5.6 workflows to explain the result and audit every claim.

## Project description

Operational teams often face a harder problem than producing another estimate: several reasonable
analytical protocols disagree, the available tail evidence is limited, and a decision still needs
to be reviewed. RIEC Guard is a working public demonstration of an auditable decision layer for
that situation. It keeps numerical analysis, evidence sufficiency, and action selection in
deterministic code, while giving reviewers a clear route from source profile to final language.

The pipeline safely profiles a dataset, confirms an explicit analysis contract, and runs grouped
RIEC-L1 over a finite candidate library. It then evaluates empirical, Gaussian-residual, and
Student-t-residual tail-headroom protocols, a whole-deployment-group bootstrap, an ordered
stability screen, and an evidence-sufficiency gate. A six-state action engine resolves those
artifacts under fixed policy. Every accepted result is connected through canonical evidence IDs
and a verified RIEC-to-protocol-to-action DAG.

Three deterministic public synthetic mechanisms make the behavior reproducible. The stable
scenario produces `pilot_range_supported` with a 0.15–0.40 mL retrospective pilot reference. The
heavy-tail scenario exposes a material protocol conflict and produces `pilot_only_conservative`
with a 0.05–0.14 mL conservative reference. The ordered-drift scenario produces
`diagnose_process_first` and no pilot interval. Each world contains 1,056 rows arranged in 12
complete deployment groups; the committed gallery records production-default 200-replicate
bootstrap results.

GPT-5.6 is deliberately downstream and bounded. Through the Responses API and strict structured
outputs, it can suggest column roles, draft an evidence-linked decision memo, and review memo
claims. Deterministic validation checks its citations, numbers, action semantics, limitations,
and claim verdicts. GPT cannot change a statistic, protocol result, action state, or pilot range.
Raw rows are not sent. An offline fixture demonstrates the complete structured workflow without
an API request, while optional live mode requires server enablement, user confirmation, and an
explicit action.

The Streamlit product opens in verified recorded mode, so judges can inspect the three accepted
outcomes immediately, view protocols and evidence lineage, run the offline fixture memo, and
download a sanitized decision packet. Recomputation is separate and explicit. The repository
also includes deterministic asset checks, AppTest and localhost smoke tools, security tests,
provenance documentation, and release auditing.

This is a public synthetic mechanism demonstration and retrospective screening aid. It is not a
calibrated industrial model, production setpoint, safety or compliance determination, causal
finding, achieved-savings claim, or universal validation. Private adapters and industrial
validation remain outside the public demonstration.

## Key features

- Grouped RIEC-L1 selection over a fixed candidate library.
- Three tail-headroom protocols, grouped bootstrap uncertainty, and explicit evidence gates.
- Six-state deterministic action engine with canonical protocol and action artifacts.
- Three reproducible, public synthetic mechanisms with recorded production-default outcomes.
- Evidence-linked GPT-5.6 memo plus deterministic-first semantic claim audit.
- Recorded and explicit-recompute Streamlit modes with an offline fixture workflow.
- Deterministic sanitized download, provenance records, and release-boundary checks.

## How Codex was used

Codex implemented and tested the public product under a human-directed, task- and gate-based
specification. It first hardened repository boundaries, the managed Python workflow, public-source
handling, contract confirmation, immutable registries, evidence identity, and lifecycle
integrity. It then translated frozen statistical requirements into the grouped RIEC engine, Fill
protocols, uncertainty and evidence gates, and the six-state action layer. Focused unit,
integration, security, golden, and property tests were used throughout, while repeated
certification-style full-suite runs were deliberately avoided until the final release macro.

The collaboration included meaningful blocker detection rather than simply generating code. In
the synthetic benchmark phase, Codex identified that the original 192-row design could not meet
the frozen 1% tail-evidence threshold. The human chose to preserve the threshold and expand each
mechanism to 1,056 rows. Codex then implemented and verified the corrected worlds instead of
weakening the evidence rule.

Codex also enforced the GPT boundary: aggregate evidence only, no raw rows, strict structured
outputs, deterministic claim precedence, safe failure behavior, and no authority over numerical
or action results. It built the fixture/live workflow, the Streamlit product, secret and download
boundaries, and release checks. Humans retained the method, policy, product decisions, scope, and
acceptance authority. Codex did not create or claim authorship of the underlying research method.

## Key human decisions

- Keep deterministic statistics and policy as the sole owners of numerical and action results.
- Keep GPT advisory, evidence-linked, and subject to a non-weakenable deterministic audit.
- Preserve the 1% evidence threshold and expand each synthetic world from 192 to 1,056 rows.
- Use three mechanisms to demonstrate protocol agreement, conflict, and ordered instability.
- Exclude non-public datasets and keep this release entirely public and synthetic.
- Separate verified recorded mode from explicit recomputation and explicit live GPT action.

## How GPT-5.6 is used

GPT-5.6 provides a bounded narrative and semantic-review layer, not an analytical engine. First,
it can propose advisory column-role mappings from a sanitized profile containing column names,
types, missing fractions, unique counts, and deterministic hints; a human must still confirm the
analysis contract. Second, it drafts a structured decision memo from accepted aggregate evidence,
including action state, protocol displays, gates, pilot endpoints, evidence IDs, and explicit
limitations. Third, it reviews claims using typed verdicts.

Every stage uses the Responses API with strict Pydantic structured output, fixed versioned
prompts, no tools, and the fixed `gpt-5.6` model. Deterministic validators check facts, citations,
numbers, units, action semantics, and prohibited claims before anything is presented. GPT cannot
alter RIEC selection, protocol results, gates, action state, or pilot range, and raw rows are not
sent. The default offline fixture exercises the same structured workflow without an API call.
Live mode is optional and requires server configuration, an in-app acknowledgement, and an
explicit user click.

## Technical stack

- Python 3.12.13 and uv with a hash-locked dependency file.
- NumPy, pandas, SciPy, scikit-learn, statsmodels, Pydantic, and JSON Schema.
- OpenAI Python SDK 2.46.0 and the Responses API with strict structured outputs.
- Streamlit 1.59.2.
- pytest, Hypothesis, Ruff, and mypy.
- Canonical JSON artifacts, SHA-256 identities, and an evidence DAG.

## Testing instructions

From the repository root, install the locked environment and run the local product:

```bash
make install
.venv/bin/python -m streamlit run streamlit_app.py
```

The no-key fixture and release checks are available with:

```bash
.venv/bin/python scripts/run_gpt_workflow.py --scenario stable_symmetric --fixture
.venv/bin/python scripts/build_demo_assets.py --check
.venv/bin/python scripts/check_streamlit_app.py --app-test
.venv/bin/python scripts/check_streamlit_app.py --server-smoke
make test
```

Detailed judge-facing steps are in `submission/TESTING_INSTRUCTIONS.md`.

## Public synthetic-data statement

All demonstration rows committed to this repository are deterministic public synthetic data.
They model transparent mechanisms for software behavior and do not reproduce or calibrate a
private operating process. Raw rows are not sent to GPT.

## Limitations

- The demonstration is a retrospective screening aid, not a production setpoint.
- It is not a safety or compliance determination, achieved-savings claim, causal conclusion, or
  universal validation.
- Synthetic mechanisms do not establish performance in an operating facility.
- Private adapters, industrial validation, and any external deployment are outside this release.
- A live GPT-5.6 check remains an explicit human checkpoint.

## External fields

Repository URL:
Supply after GitHub push.

Working demo URL:
Supply after Streamlit deployment.

Public YouTube video URL:
Supply after upload.

Primary Codex /feedback Session ID:
Run /feedback in the principal Codex build thread and paste the returned ID into
Devpost.
