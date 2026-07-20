# Testing Instructions

These instructions exercise the committed public synthetic demonstration. They do not require
benchmark regeneration, a private adapter, an OpenAI API key, or an external deployment.

## Prerequisites and supported platform

- Git.
- uv 0.11.29.
- A Python 3.12 runtime; `make install` manages CPython 3.12.13 directly.
- A local browser for the Streamlit interface.

The release environment was verified with CPython 3.12.13 and Streamlit 1.59.2 on macOS arm64.
The package requires Python `>=3.12,<3.13`; the documented deployment target is a standard
Streamlit host using Python 3.12. External hosted deployment remains a human checkpoint.

## Clone and locked setup

Clone the repository using the public repository URL after the human release owner supplies it.
This document intentionally does not invent an external URL. Enter the cloned repository root,
then run:

```bash
uv --version
make install
.venv/bin/python --version
```

`make install` creates `.venv` with Python 3.12.13, synchronizes the exact hashes in
`requirements.lock`, and installs the local package editable with no dependency resolution. The
workflow does not depend on a global `python` alias.

## Launch without an API key

Do not set `OPENAI_API_KEY`. From the repository root, run:

```bash
unset OPENAI_API_KEY
export RIEC_GUARD_LIVE_GPT_ENABLED=false
.venv/bin/python -m streamlit run streamlit_app.py
```

Open the local address printed by Streamlit. The default selection is **Stable symmetric
process** in verified recorded mode. Expected result:

- action state: `pilot_range_supported`;
- controlled retrospective pilot reference: `0.15–0.40 mL`;
- protocol conflict: false;
- offline fixture control: available;
- live GPT-5.6: disabled.

Ordinary app load validates committed assets and does not rerun the statistical pipeline.

## Switch the three scenarios

Use the scenario selector at the top of the app. Confirm these recorded outcomes:

1. **Stable symmetric process** — `pilot_range_supported`, `0.15–0.40 mL`.
2. **Heavy-tail particulate variation** — `pilot_only_conservative`, protocol conflict, and
   `0.05–0.14 mL` conservative retrospective reference.
3. **Batch drift and change point** — `diagnose_process_first`, ordered-stability warning, and no
   pilot interval.

The Decision, Evidence, GPT-5.6, and Method tabs should remain available for every scenario.
Rebuilding benchmark assets is neither necessary nor part of this review.

## Offline fixture GPT workflow

In the GPT-5.6 tab, click **Generate offline fixture memo**. The fixture makes no API request. It
should display the advisory mapping, an evidence-linked memo, a passing claim audit, and three
fixture call records. Switching scenarios clears the displayed narrative so that one scenario's
memo cannot appear under another scenario.

The same workflow can be exercised from the command line:

```bash
.venv/bin/python scripts/run_gpt_workflow.py \
  --scenario stable_symmetric \
  --fixture
```

Expected compact output includes `"status": "completed"`, `"fixture_non_live": true`, requested
model `gpt-5.6`, action state `pilot_range_supported`, and a passing claim audit.

## Sanitized decision download

In the app, click **Download sanitized decision packet**. Inspect the downloaded JSON. It may
contain the scenario, policy display, accepted action, aggregate protocol/gate/evidence facts,
limitations, and optional safe GPT projection. It must not contain raw rows, CSV contents,
residuals, row predictions, local paths, environment values, credentials, full prompts, hidden
reasoning, exception text, or traces.

## Optional live GPT-5.6 human checkpoint

Do not put a key into the browser. A human may perform one separately authorized command-line
smoke through server-side environment variables:

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

A successful manually authorized run should request `gpt-5.6`, return response IDs, generate the
memo, produce an audit pass or safe revision result, send no raw rows, and print no secret. This
check has not been executed as part of the local release preparation.

## Deterministic asset check

```bash
.venv/bin/python scripts/build_demo_assets.py --check
```

Expected result: `Public demo asset check passed: 3 scenarios (recorded output, no analysis)`.
This check verifies committed bytes, identities, and metadata without benchmark recomputation.

## Streamlit AppTest

```bash
.venv/bin/python scripts/check_streamlit_app.py --app-test
```

Expected result: a pass for the stable recorded mode, available fixture, and disabled live mode.

## Localhost server smoke

```bash
.venv/bin/python scripts/check_streamlit_app.py --server-smoke
```

Expected result: the fixed localhost health endpoint returns HTTP 200 and the temporary server is
stopped. This command does not deploy the application externally.

## Full tests and quality checks

Run the repository suite once:

```bash
make test
```

The release-layer focused test is:

```bash
.venv/bin/python -m pytest -p no:cacheprovider \
  tests/release/test_build_week_release.py
```

Static and public-boundary checks are:

```bash
make lint
make type-check
make release-scan
```

`make release-scan` runs repository cleanup first and removes `.venv`. Run it last, or run
`make install` again before additional local development commands.

## Limitations

- All committed demonstrations use public synthetic data.
- Recorded outcomes are retrospective screening references, not production setpoints.
- They are not safety or compliance determinations, causal findings, achieved-savings claims, or
  universal validation.
- Raw rows are not sent to GPT.
- Private adapters, industrial validation, and public hosted availability are outside this local
  release candidate.
