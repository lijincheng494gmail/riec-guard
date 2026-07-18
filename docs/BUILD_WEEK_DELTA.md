# Build Week Delta

RIEC Guard combines an existing research foundation with a new clean-room productization layer.
Only competition-period additions supported by dated commits, tests, and human acceptance are
presented as Build Week work.

## Verified completed work through accepted TASK-004

| Category | Implemented evidence | Status |
|---|---|---|
| Clean-room public repository | Sole Git root, 89-file seed provenance, baseline commit, denylist checks | Human accepted in TASK-001 |
| Reproducible toolchain | uv workflow, managed CPython 3.12.13, exact universal hash lock, test/lint/type/scan commands | Human accepted in TASK-002 |
| Public/private physical separation | Public-first immutable settings, disjoint roots, hosted private-mode block, generated run roots outside Git | Human accepted in TASK-003 |
| Demo-safe source boundary | Unified built-in/upload source type, bounded CSV validation, generated storage names, run ownership, idempotent and symlink-resistant cleanup | Human accepted in TASK-004 |
| Prior/new and Codex evidence records | Boundary documents, dated timeline, stable collaboration records, and human decision log | Implemented in TASK-005; human acceptance and commit evidence are recorded externally after this commit |

The public release gate for Stage 0 has not yet passed; TASK-006 remains required.

## Planned Build Week product work—not yet implemented

The following are concrete Build Week targets, not claims of current functionality:

| Delta category | Planned product work | Activation evidence |
|---|---|---|
| Typed AuditContract architecture | Wire canonical/GPT schemas, typed models, deterministic profiling, contract validation/confirmation, registries, and manifest foundation | TASK-007–TASK-013 and Gate G1 |
| Grouped RIEC-L1 product engine | Canonical Fill domain model, exact leave-one-deployment-group-out evaluation, finite candidate registry, complete ledger, row-weighted grouped risk, ties/equivalence sets, and switchpoints | TASK-014–TASK-023 and Gate G2 |
| Fill protocols and guardrails | Empirical/Gaussian/Student-t headroom, whole-group bootstrap, ordered stability, evidence sufficiency, policy sensitivity, six-state action engine, bounded pilot ranges | TASK-024–TASK-034 and Gate G3 |
| Mechanism-based synthetic benchmarks | Six public mechanism worlds, research oracles, fingerprints, benchmark matrix, and grouped-versus-row evidence | TASK-035–TASK-040 and Gate G4 |
| GPT-5.6 runtime | Structured AuditContract compilation, read-only evidence tools, evidence-linked memo drafting, deterministic binding, and claim auditing | TASK-041–TASK-048 and Gate G5 |
| Streamlit workflow | Source/policy/contract screens, audit progress, evidence/conflict explorer, memo/claim audit, and export flow | TASK-049–TASK-055 and Gate G6 |
| Audit bundle, tests, and deployment | Self-contained bundle/checksums, hosted-demo hardening, integration/performance checks, packaging, and deployment | TASK-053–TASK-055 and Gate G6 |
| Submission materials | Release licensing/citation scan, research outputs, final README/testing evidence, Devpost text, screenshots, video, and release-candidate audit | TASK-056–TASK-060 and Gate G7 |

The seed includes architecture documents, schemas, configuration, and interface scaffolding. Their
presence does not mean the corresponding runtime stages have been implemented or validated.

## Release-claim activation rules

- The repository may now claim a dated clean-room baseline, pinned toolchain, public-first runtime
  roots, and guarded ephemeral CSV source handling.
- It may claim exact RIEC-L1 product-engine fidelity only after TASK-023/Gate G2 passes.
- It may claim working Fill protocols, uncertainty, and action guardrails only after
  TASK-034/Gate G3 passes.
- It may claim a verified public mechanism benchmark only after TASK-040/Gate G4 passes.
- It may claim live GPT-5.6 contract/memo/claim-audit stages only after the live harness and
  TASK-048/Gate G5 pass; a mock or fallback is not a live claim.
- It may claim a complete deployed web product only after TASK-055/Gate G6 passes.
- It may claim release readiness only after TASK-060/Gate G7 passes.
- No gate activates claims of achieved savings, compliance, a production setpoint, successful
  live industrial deployment, causal effect, or universal cross-domain validation.

## Verified Build Week timeline

Dates below come only from the official rules snapshot, frozen paper metadata, or Git commit
metadata. Git timestamps retain their recorded ISO-8601 offset.

| Date/time | Verified event | Evidence |
|---|---|---|
| `2026-07-13T09:00:00-07:00` | Official OpenAI Build Week Submission Period opened | Devpost Official Rules snapshot dated 2026-07-18 |
| `2026-07-16` | RIEC-L1 article became available online; the method itself remains prior research | Frozen Phase A publication-boundary metadata; DOI `10.1016/j.array.2026.101097` |
| **`2026-07-18T20:10:42+08:00`** | **Public repository baseline / TASK-001** | **`876f661f4c9d9e8b24c3e7a30848dc903c248a0a`** — `task(TASK-001): initialize clean-room public repository` |
| `2026-07-18T21:33:36+08:00` | TASK-002 toolchain and quality workflow | `57bfcde8b7e2f3abdfb050ef93e7d5c70647293e` — `task(TASK-002): pin toolchain and quality workflow` |
| `2026-07-18T22:45:52+08:00` | TASK-003 public-first disjoint run roots | `87afe22dc12b4dd327c87708a51f123597afe517` — `task(TASK-003): enforce public-first disjoint run roots` |
| `2026-07-19T00:38:09+08:00` | TASK-004 upload guard and ephemeral run management | `7bfb78b9691b2bca527059acf16a50e006005dbc` — `task(TASK-004): add safe upload and ephemeral run management` |

**Exact clean-room baseline commit:**
`876f661f4c9d9e8b24c3e7a30848dc903c248a0a`.

TASK-005’s commit cannot embed its own final SHA. Its SHA is recorded in the external TASK-005
execution report after commit creation.

## Evidence protocol

Each formal task records its objective, human-owned decision, Codex contribution, verification,
commit/evidence reference, and status in [CODEX_COLLABORATION.md](CODEX_COLLABORATION.md). Human
acceptance remains separate from Codex implementation. Planned work becomes an active release
claim only after its named task and gate are accepted.
