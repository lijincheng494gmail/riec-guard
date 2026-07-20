# Streamlit deployment

RIEC Guard is prepared for local use and deployment on a standard Streamlit host. This
document does not claim or create an external deployment.

## Local fixture-only start

From the repository root on branch `build-week-2026`, run:

```bash
.venv/bin/python -m streamlit run streamlit_app.py
```

The app starts without secrets. It serves the verified recorded deterministic audit,
allows an explicit deterministic recomputation, and keeps the offline fixture narrative
available. With no live configuration it displays:

> Live GPT-5.6 is not configured on this deployment.
>
> The deterministic audit and offline fixture demonstration remain available.

## Local live-GPT start

Configure the key only in the server environment, explicitly enable live mode, and then
start the same entry point:

```bash
export OPENAI_API_KEY="<deployment-secret>"
export RIEC_GUARD_LIVE_GPT_ENABLED="true"
.venv/bin/python -m streamlit run streamlit_app.py
```

The app has no API-key input. A live request remains unavailable until both server-side
values are configured, and it still requires the in-app confirmation and an explicit
button click. The model is fixed to `gpt-5.6`.

## Hosted deployment settings

- Deployment branch: `build-week-2026`
- Repository-root entry point: `streamlit_app.py`
- Python runtime: 3.12
- Server-side secrets: `OPENAI_API_KEY` and `RIEC_GUARD_LIVE_GPT_ENABLED`
- Live enable values: `true`, `1`, or `yes`; every other value disables live mode

Copy the names from `.streamlit/secrets.toml.example` into the host's protected secrets
manager. Never commit `.streamlit/secrets.toml` or a real key.

To disable live GPT immediately, set `RIEC_GUARD_LIVE_GPT_ENABLED` to `false` (or remove
it), remove the deployed key if it is no longer needed, and restart the app. The recorded
deterministic audit and offline fixture remain available.

## Boundary and health check

This public demo uses committed synthetic scenarios. GPT receives sanitized aggregate
facts only; raw rows and CSV contents are not sent to GPT. The result is a retrospective
screening aid, not a production setpoint or safety, compliance, or achieved-savings
determination.

After a local start on the default port, check Streamlit itself with:

```bash
curl --fail --silent --show-error http://127.0.0.1:8501/_stcore/health
```

The bounded repository checks are also available from the repository root:

```bash
.venv/bin/python scripts/check_streamlit_app.py --app-test
.venv/bin/python scripts/check_streamlit_app.py --server-smoke
```
