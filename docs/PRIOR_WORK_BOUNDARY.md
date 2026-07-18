# Prior Work Boundary

This document separates the published research and historical engineering work that predated the
OpenAI Build Week Submission Period from the product work recorded in this repository. The
official Submission Period began on **2026-07-13 at 09:00 Pacific Time**.

## Prior-work inventory

| Prior-work category | What existed before Build Week | Use in RIEC Guard | Public-release boundary |
|---|---|---|---|
| RIEC-L1 methodology | The finite-candidate evidence-led conflict-resolution method, including its mathematical definitions and research rationale | Cited methodological foundation; product behavior must be reimplemented and fidelity-tested in new code | RIEC-L1 was not invented during Build Week |
| Peer-reviewed Array paper | J. Li, Y. Zhao, and X. Li, “RIEC-L1: An evidence-led conflict-resolution layer for finite candidate libraries in engineering data,” *Array* (2026), DOI [`10.1016/j.array.2026.101097`](https://doi.org/10.1016/j.array.2026.101097) | Normal scholarly citation and method contract | DOI and citation only; no publisher-formatted PDF, page, layout, screenshot, or logo |
| Three historical engineering cases | Project 2 residence-time-distribution (RTD), drying, and optics cases, with earlier runtime/results | Method references and, only when cleared, golden expected values | No wholesale code/result-tree import; no claim that historical cases are new product validation |
| Historical dairy work | Earlier retrospective dairy analysis, private industrial data, and manuscript/submission materials | Private-local research anchor only | Private dairy rows, identifiers, manuscripts, publisher files, and submission materials are absent from this repository and public release |
| Earlier Fill starter/demo | Pre-existing RIEC-Fill concept, scripts, documentation, and labels-based synthetic demo | Design input; unsafe/incomplete behavior is to be replaced through task-scoped implementation | The starter is not this public repository and is not presented as a complete RIEC-L1 engine or Build Week product |
| Reusable governance patterns | Protocol typing, evidence ledgers, claim boundaries, downgrade rules, and related patterns derived from earlier engineering projects | Reimplemented from frozen specifications when a task authorizes it | No historical archives, private results, manuscripts, or unclear-license source code are copied |
| Phase A–D planning/audit records | Build Week planning inputs and frozen specifications | Human-owned product/method requirements for Codex task contracts | Planning evidence is not product runtime code and is not claimed as Codex implementation |

## Required distinctions

- **RIEC-L1 was not invented during Build Week.** The method and underlying research predate the
  competition implementation.
- The paper became available online on **2026-07-16**, during the Submission Period, but it reports
  prior research. Publication timing does not make the method new Build Week work.
- The paper is methodological support for implementing RIEC-L1. It is not peer review or
  validation of RIEC Guard, Fill Pack, its UI, its GPT-5.6 runtime, its public benchmark, or its
  product claims.
- The public repository baseline was created during Build Week. It does not prove that every file
  or idea in the seed originated during Build Week; the reuse classifications below remain
  controlling.
- No statement in this repository should imply that the current product, Streamlit workflow,
  GPT-5.6 runtime, public mechanism benchmark, or clean-room repository existed before Build Week
  unless dated evidence supports that specific statement.

## Reuse classifications

Every reused item that later enters this repository must be classified as one of:

- `cited_reference` — a citation or method reference; no code copied;
- `golden_fixture` — cleared expected values used only for deterministic fidelity tests;
- `reimplemented` — behavior newly written from a specification;
- `adapted_with_attribution` — cleared code adapted with ownership and license recorded; or
- `new_build_week_work` — created in this repository during the Submission Period.

Any reuse record must identify its source, owner, license/permission basis, first introducing
commit, and reason for inclusion. Copying historical code into a new repository does not make it
new work.

## Build Week implementation boundary

The Build Week productization target includes the clean public repository, physical public/private
separation, typed AuditContract architecture, grouped RIEC-L1 product engine, Fill protocols and
guardrails, mechanism benchmarks, controlled GPT-5.6 stages, Streamlit workflow, audit bundle,
tests, deployment, and submission evidence. These are Build Week claims only after the relevant
task and gate pass. Current implementation status is recorded in
[BUILD_WEEK_DELTA.md](BUILD_WEEK_DELTA.md).

## Claim and intellectual-property boundary

Permitted wording distinguishes a **peer-reviewed method** and **published research foundation**
from a **Build Week product implementation**. A retrospective screening or pilot reference is not
a production setpoint, compliance finding, achieved saving, causal effect, successful live
deployment, or universal cross-domain validation.

The public release contains no Elsevier or Array logo, publisher screenshot, publisher-formatted
PDF, manuscript submission file, historical archive, or private industrial data. Historical
publisher and submission materials remain outside the public repository.
