# Prior Work Boundary

Purpose: distinguish research/code that existed before the Build Week submission period from the product work to be created and judged during Build Week.

## 1. Prior work inventory

| Prior asset | Status | Treatment in RIEC Guard | Public repository rule |
|---|---|---|---|
| RIEC-L1 paper in Array, DOI `10.1016/j.array.2026.101097` | published research | cite as methodological foundation; restate formulas in original engineering documentation | DOI/citation only; do not bundle publisher PDF/layout |
| Project 2 RIEC runtime and three engineering cases | pre-existing code/results | use as method-reference and golden fixtures; reimplement the complete ledger in new code | no wholesale workspace copy; record any adapted function and ownership/license basis |
| Existing RIEC-Fill starter code/docs | pre-existing concept demo | preserve as a local snapshot; replace unsafe runner, protocol typing, action logic, benchmark, and output structure | not the public repo; current outputs are denied |
| Current synthetic CSV | pre-existing demo data | replace with Build Week mechanism generator and newly generated fixtures | do not market the old labels-only generator as domain-aware |
| Private dairy data and current dairy manuscript/assets | private pre-existing industrial research | local-only anchor and manuscript reference | never auto-load, deploy, commit, screenshot, or send raw rows to GPT by default |
| Projects 1, 3, 4, 5, 6, and 7 | pre-existing research/code | use only the Phase B pattern library unless a specific module is cleared and documented | no historical result trees, raw data, manuscripts, nested archives, or unclear-license code |
| Phase A/B/C planning and audit documents | Build Week planning artifacts, not Codex implementation | inputs to architecture/task design; may be summarized in collaboration log | do not mislabel as product code or Codex output |

## 2. Build Week product work

The following must be newly written or meaningfully reimplemented in the clean RIEC Guard repository:

- public/private repository architecture and release gates;
- typed AuditContract and validation layer;
- versioned candidate/protocol registry;
- complete published-compatible RIEC-L1 ledger and diagnostics;
- group-aware splits, group bootstrap, and ordered stability gates;
- mechanism-based synthetic benchmark and oracle evaluation;
- ordered action state machine and claim-eligibility guardrails;
- immutable evidence IDs, claim map, report bundle, and run provenance;
- GPT-5.6 contract compiler, tool orchestration, memo drafting, and claim audit;
- web UI, CLI/service layer, tests, deployment, and judging instructions;
- Build Week README, Codex collaboration log, video, screenshots, and submission text.

## 3. Reuse classifications

Every reused item added to the new repository must be recorded as exactly one of:

- `cited_reference` — no code copied;
- `golden_fixture` — output values used only for tests;
- `reimplemented` — behavior rewritten from specification;
- `adapted_with_attribution` — code adapted with ownership/license basis;
- `new_build_week_work` — created in the new repository during the submission period.

The record must include source package/path, owner if known, license/permission basis, first commit, and reason for inclusion.

## 4. Claims the submission may make

- RIEC Guard builds on the peer-reviewed RIEC-L1 method.
- The paper became available online during Build Week.
- The new product architecture, Fill Pack, GPT-5.6 workflow, benchmark, UI, tests, and deployment were created/meaningfully extended during Build Week, if commit/session evidence confirms this.
- Prior dairy and cross-project work informed the design.

## 5. Claims the submission may not make

- the RIEC-L1 method or Array paper was created during Build Week;
- the existing starter was entirely built with Codex/GPT-5.6;
- historical code is new because it was copied into a new repository;
- private dairy evidence is publicly reproducible;
- publisher graphics or prior submission assets are original Build Week artwork.

## 6. Required repository evidence

The public repository must contain:

```text
PRIOR_WORK_BOUNDARY.md
BUILD_WEEK_DELTA.md
CODEX_COLLABORATION.md
THIRD_PARTY_NOTICES.md
DATA_PROVENANCE.md
```

The main Codex thread must hold the majority of core implementation and produce the `/feedback` Session ID required by the submission form.
