
# RIEC Guard

**Auditable decisions from conflicting evidence.**

This directory is the clean-room public repository seed for **RIEC Guard - Fill Pack**, a
Work & Productivity project built during OpenAI Build Week. It is intentionally not a
working product yet. The implementation is governed by the Phase E Codex task queue.

## Research foundation

RIEC Guard builds on the peer-reviewed method:

> J. Li, Y. Zhao, and X. Li, "RIEC-L1: An evidence-led conflict-resolution layer for finite
> candidate libraries in engineering data," *Array* (2026), DOI:
> `10.1016/j.array.2026.101097`.

The paper and historical starter are **prior work**. The clean-room engine, Fill Pack,
GPT-5.6 workflow, web product, tests, deployment, and claim-audit pipeline are the
Build Week extension. See `docs/PRIOR_WORK_BOUNDARY.md` and `docs/BUILD_WEEK_DELTA.md`.

## Safety boundary

- Public mode is the only seed mode.
- No private industrial row belongs in this repository.
- GPT never owns statistical calculations.
- A screening pilot reference is not a production setpoint, compliance decision, or
  achieved saving.

## Start

From the command-pack root, read `00_READ_THIS_FIRST_CN.txt`, then paste
`01_START_PROMPT_FOR_CODEX.txt` into the main Codex GPT-5.6 Sol thread. Execute only
`TASK-001` first.

Seed validation:

```bash
python scripts/validate_seed.py
python -m pytest
python scripts/public_release_scan.py .
```
