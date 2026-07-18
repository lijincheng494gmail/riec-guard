
# RIEC Guard

**Auditable decisions from conflicting evidence.**

This is the clean-room public repository for **RIEC Guard — Fill Pack**, an OpenAI Build Week
Work & Productivity project. Development is task- and gate-driven; implemented status is recorded
separately from planned functionality.

## Prior research and Build Week work

RIEC Guard builds on the prior peer-reviewed **RIEC-L1 method**:

> J. Li, Y. Zhao, and X. Li, "RIEC-L1: An evidence-led conflict-resolution layer for finite
> candidate libraries in engineering data," *Array* (2026), DOI:
> `10.1016/j.array.2026.101097`.

RIEC-L1 and the historical engineering cases, dairy analysis, and Fill starter predate this
repository. The paper supports the methodology; it does not peer-review or validate this product.
During Build Week, this repository is building the clean-room Fill product layer, controlled
GPT-5.6 workflow, public mechanism benchmark, UI, evidence bundle, and release evidence. Only
competition-period additions verified by dated commits and human acceptance are presented as
Build Week work.

See the detailed [prior-work boundary](docs/PRIOR_WORK_BOUNDARY.md),
[Build Week delta and timeline](docs/BUILD_WEEK_DELTA.md),
[Codex collaboration record](docs/CODEX_COLLABORATION.md), and
[human decision log](docs/DECISION_LOG.md).

## Safety boundary

- Public mode is the only seed mode.
- No private industrial row belongs in this repository.
- GPT never owns statistical calculations.
- A screening pilot reference is not a production setpoint, compliance decision, or
  achieved saving.

## Development status and testing

The clean-room repository, pinned toolchain, public-first runtime roots, and guarded ephemeral CSV
source layer are implemented through accepted TASK-004. The AuditContract runtime, grouped engine,
protocols, GPT-5.6 stages, Streamlit workflow, deployment, and final submission package remain
planned until their named tasks and gates pass.

Use the managed Python workflow documented in [testing instructions](docs/TESTING_INSTRUCTIONS.md):

```bash
make install
make test
make lint
make type-check
```
