# Streamlit deployment

RIEC Guard is ready for a human-authorized deployment on a standard Streamlit
host. No external deployment was performed as part of this repository release.

## Deployment contract

- Branch: `build-week-2026`
- Repository-root entry point: `streamlit_app.py`
- Python: 3.12
- Dependencies: the exact hash-locked `requirements.lock`
- Public data: the three committed synthetic scenarios
- Default mode: verified recorded deterministic audit
- Optional live model: fixed to `gpt-5.6`

Judges and deployers do not need to regenerate the benchmark assets.

## Local fixture-only start

After installing the managed environment from the repository instructions, run
from the repository root:

```bash
.venv/bin/python -m streamlit run streamlit_app.py
```

No secret is required. The app verifies and displays the committed deterministic
record, permits recomputation only through `Recompute deterministic audit`, and
offers `Generate offline fixture memo`. The fixture executes the structured GPT
workflow without an API request.

With no live configuration, the app displays:

> Live GPT-5.6 is not configured on this deployment.
>
> The deterministic audit and offline fixture demonstration remain available.

## Optional local live-GPT start

Configure both values in the server environment and start the same entry point:

```bash
export OPENAI_API_KEY="<deployment-secret>"
export RIEC_GUARD_LIVE_GPT_ENABLED="true"
.venv/bin/python -m streamlit run streamlit_app.py
```

The enable flag accepts only `true`, `1`, or `yes`, ignoring case and surrounding
whitespace. Every other value disables live mode. The app has no credential input,
model selector, or prompt editor.

Configuration alone does not make a request. A user must also select the
acknowledgement checkbox and click `Generate with live GPT-5.6`. The handler checks
the server-side configuration again and allows at most one successful live workflow
per scenario per session. Results remain session-local.

Unset both values after local use:

```bash
unset OPENAI_API_KEY
unset RIEC_GUARD_LIVE_GPT_ENABLED
```

## Streamlit-host configuration

1. Select branch `build-week-2026`.
2. Set the app file to repository-root `streamlit_app.py`.
3. Select a Python 3.12 runtime.
4. Install the locked dependencies according to the repository setup instructions.
5. Launch with no secrets for recorded and fixture-only operation.
6. Only if a live demonstration is explicitly authorized, add
   `OPENAI_API_KEY` and `RIEC_GUARD_LIVE_GPT_ENABLED` through the host's protected
   secret manager.
7. Verify all three scenarios, the fixture workflow, and the sanitized download.

`.streamlit/secrets.toml.example` documents the names only. Never commit an actual
`.streamlit/secrets.toml` or a real credential. To disable live GPT, remove the
enable flag or set it to `false`, remove the credential when no longer needed, and
restart the app. Recorded deterministic and fixture operation remain available.

## Recorded and recompute behavior

Ordinary page load and scenario changes use sealed recorded results bound to the
committed CSV, catalog, summary, policy, action, and evidence hashes. They do not
run the statistical pipeline.

The explicit recompute button runs the selected allowlisted scenario through the
accepted deterministic services with 200 whole-deployment-group bootstrap
replicates. A recompute failure does not invalidate the verified recorded result.

## Health and bounded checks

After a local start on Streamlit's default port:

```bash
curl --fail --silent --show-error http://127.0.0.1:8501/_stcore/health
```

Repository-level checks are available from the repository root:

```bash
.venv/bin/python scripts/check_streamlit_app.py --app-test
.venv/bin/python scripts/check_streamlit_app.py --server-smoke
```

The server smoke binds only to localhost and terminates its child process. Neither
command invokes live GPT.

## Public boundary and limitations

GPT receives sanitized aggregate facts and evidence identities only. Raw rows, CSV
contents, residual arrays, row predictions, local paths, credentials, prompts, and
runtime traces are excluded. The downloadable decision packet is allowlisted JSON
built in memory.

This is a public synthetic mechanism demonstration for retrospective screening. It
is not a production setpoint, safety or compliance determination, causal result,
achieved-savings claim, or proof of an external deployment. Industrial validation
and external release actions remain separate human checkpoints.
