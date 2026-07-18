# Codex Collaboration Record

## Ownership and operating model

The human project director owns product scope, the research method, candidate/protocol boundaries,
claim language, acceptance decisions, and activation of every formal task or repair slot. Codex
implements, tests, documents, and repairs work under those task contracts. Codex did not originate
or peer-review the prior RIEC-L1 method and does not own numerical or product decisions.

The main GPT-5.6 Sol Codex thread remains the primary implementation and `/feedback` thread.

## Stable record format

Every entry contains:

- **Task ID and timestamp** — formal task and dated evidence point;
- **Objective** — contracted result;
- **Human-owned decision** — product/method/boundary choice retained by Codex;
- **Codex contribution** — implementation, verification, or documentation performed;
- **Tests and verification** — exact accepted evidence summary;
- **Commit/evidence reference** — immutable commit or external report rule;
- **Status** — human acceptance state and blocker/repair state.

## TASK-001 — 2026-07-18T20:10:42+08:00

- **Objective:** Initialize the supplied public seed as the sole clean-room Git repository.
- **Human-owned decision:** Keep historical/private material outside the public repository and
  preserve the frozen method, evidence, action, and claim boundaries.
- **Codex contribution:** Audited repository boundaries, computed the 89-file seed manifest
  SHA-256 `d4dc444298f58e9de298d64ca508c3a8a7088f8a5b3fcceff1bbedfad3e233f7`,
  initialized branch `build-week-2026`, and created the baseline commit.
- **Tests and verification:** Seed validation passed with 29 JSON artifacts; 3 pytest tests passed;
  public release scan passed; denylisted tracked-file query returned no matches.
- **Commit/evidence reference:** `876f661f4c9d9e8b24c3e7a30848dc903c248a0a` and external
  `EXECUTION_REPORTS/TASK-001.md`.
- **Status:** Human accepted; no blocker or repair slot.

## TASK-002 — 2026-07-18T21:33:36+08:00

- **Objective:** Pin one reproducible Python 3.12 application/development workflow.
- **Human-owned decision:** Use uv, managed CPython 3.12.13, exact `requirements.lock`, and no
  unapproved `uv.lock` or runtime dependency downloader.
- **Codex contribution:** Compiled the universal hash lock, documented deterministic install and
  quality commands, and verified a genuinely clean environment.
- **Tests and verification:** Clean install passed; 3 pytest tests passed; Ruff passed; mypy found
  no issues in 24 files; release scan and diff checks passed; lock SHA-256
  `82116ddca67ef3da9b8bbf54942eb186cfcf6ace0b284dfdeabba9644effb76e`.
- **Commit/evidence reference:** `57bfcde8b7e2f3abdfb050ef93e7d5c70647293e` and external
  `EXECUTION_REPORTS/TASK-002.md`.
- **Status:** Human accepted; no blocker or repair slot.

## TASK-003 — 2026-07-18T22:45:52+08:00

- **Objective:** Implement public-first settings and physically disjoint run roots.
- **Human-owned decision:** Public mode is the hosted default; private mode is local-only; public,
  private, and repository roots must not overlap; all run/storage IDs are generated internally.
- **Codex contribution:** Implemented immutable settings, safe environment parsing, root
  validation, hosted private-mode rejection, generated run layout, and safe public messages.
- **Tests and verification:** Focused security suite: 10 passed; full suite: 13 passed; Ruff passed;
  mypy found no issues in 26 files; release scan and diff checks passed.
- **Commit/evidence reference:** `87afe22dc12b4dd327c87708a51f123597afe517` and external
  `EXECUTION_REPORTS/TASK-003.md`.
- **Status:** Human accepted; no blocker or repair slot.

## TASK-004 — 2026-07-19T00:38:09+08:00

- **Objective:** Add a demo-safe upload guard and explicit ephemeral run manager.
- **Human-owned decision:** CSV-only public uploads use frozen 10 MiB/100,000-row/100-column
  limits, generated storage names, owning-run authorization, and fail-closed cleanup.
- **Codex contribution:** Implemented the unified source abstraction, bounded UTF-8 CSV
  normalization, signature/name/path guards, stable errors, cross-run isolation, and idempotent
  symlink-resistant cleanup primitives.
- **Tests and verification:** Focused upload/security suite: 55 passed; full suite: 68 passed; Ruff
  passed; mypy found no issues in 29 files; release scan and diff checks passed; dependency lock
  remained unchanged.
- **Commit/evidence reference:** `7bfb78b9691b2bca527059acf16a50e006005dbc` and external
  `EXECUTION_REPORTS/TASK-004.md`.
- **Status:** Human accepted; no blocker or repair slot.

## TASK-005 — 2026-07-19

- **Objective:** Freeze prior-work, Build Week delta, Codex evidence, and human decision records.
- **Human-owned decision:** Present RIEC-L1 as prior peer-reviewed research; activate Build Week
  product claims only after task/gate evidence; keep publisher/private material outside release.
- **Codex contribution:** Reconciled frozen boundary documents, official dates, accepted reports,
  and Git metadata into a visible README section, concrete status/timeline, stable collaboration
  entries, and twelve-entry human decision log.
- **Tests and verification:** Documentation structure/content checks passed; full suite: 68 passed;
  Ruff passed; mypy found no issues in 29 files; public release scan and diff checks passed.
- **Commit/evidence reference:** TASK-005 commit SHA is recorded in the external execution report
  after commit creation; external record: `EXECUTION_REPORTS/TASK-005.md`.
- **Status:** Implemented; pending human acceptance; no blocker or repair slot.
