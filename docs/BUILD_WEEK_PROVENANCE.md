# Build Week provenance

This document records what predates OpenAI Build Week 2026, what was implemented or meaningfully
extended during the event, and how human direction, Codex implementation, deterministic analysis,
and GPT-5.6 runtime assistance remain separated.

## Pre-existing research boundary

The RIEC-L1 research concept and its peer-reviewed methodological lineage predate Build Week. The
underlying idea of resolving evidence across a finite candidate library was not created by Codex
and is not claimed as a Build Week invention. This repository does not infer or reproduce a
publication URL, author list, bibliographic identifier, or other citation metadata. The current
public product has not been presented as peer-reviewed or industrially validated.

## Built or meaningfully extended during Build Week

The dated repository work created or materially extended:

- the hardened, secure public-source and confirmed-contract workflow;
- grouped RIEC-L1 selection over the fixed candidate library;
- Fill headroom protocols H1, H2, and H3, plus U1 whole-group uncertainty;
- G1 ordered stability and G2 evidence sufficiency;
- deterministic conflict summarization and the six-state action engine;
- three public synthetic mechanisms and sealed recorded results;
- the structured GPT-5.6 mapping, evidence memo, and claim-audit workflow;
- the Streamlit application, recorded/recompute separation, and sanitized download;
- focused verification and local release/testing infrastructure.

## Dated Git timeline

The timestamps below come directly from Git and use the recorded `+08:00` offset.

| Milestone | Commit | Git timestamp | Feature summary |
|---|---|---|---|
| G1 baseline | `d42f65c7ee04c21792468377d53956a1a904bfd1` | `2026-07-20T06:44:00+08:00` | Passed the canonical contract gate after privacy and provenance repairs. |
| MACRO-01 | `a4f67564b8d23c6a62cb747e3b54c080366486dd` | `2026-07-20T08:07:35+08:00` | Added the grouped RIEC-L1 core, exact grouped cross-validation, selection, and aggregate evidence. |
| MACRO-02 | `fe56580766b14b70da8efb047d996480fd3371de` | `2026-07-20T10:35:21+08:00` | Added Fill protocols, uncertainty/stability/evidence gates, conflict logic, and the action engine. |
| MACRO-03 | `61f8f15dfa1bc0e47c1a1d2f75fea135299fc3b2` | `2026-07-20T14:50:01+08:00` | Added three 1,056-row synthetic worlds and sealed production-default demo results. |
| MACRO-04 | `e0fad6869b160988a03b44256b2de6ab72829a2c` | `2026-07-20T18:08:20+08:00` | Added the bounded GPT-5.6 structured workflow, memo validation, and claim audit. |
| MACRO-05 | `afbbae5d0f597a973cb6c8a265677c7b0d839f25` | `2026-07-20T19:47:24+08:00` | Added the public Streamlit product, deployment guidance, and UI boundary tests. |

This tracked timeline intentionally ends at the accepted MACRO-05 baseline. The MACRO-06 release
commit and annotated local tag are verified only after the commit exists; no unknown SHA is placed
in tracked documentation.

## Key human-directed decisions

- Deterministic statistics own all numerical results, gates, action states, and pilot ranges.
- GPT remains advisory, evidence-linked, and auditable; it cannot change the decision.
- The frozen 1% tail-evidence threshold was not weakened when the first benchmark design failed.
- Each synthetic world was expanded from 192 rows to 1,056 rows, yielding 528 rows and 5.28
  expected tail observations per product.
- Three mechanisms were retained to demonstrate agreement, protocol conflict, and instability.
- Private dairy data and other industrial rows were excluded from the public repository.
- Recorded verification is separated from explicit statistical recomputation.
- Live GPT requires server enablement, user confirmation, and an explicit action.

## Codex contribution

Under human-written constraints, Codex hardened the repository, implemented the public grouped
engine and product layers, wrote focused unit/integration/security/golden tests, enforced frozen
statistical specifications, built the GPT boundary and Streamlit interface, and added release
checks. It also stopped on valid blockers. In particular, Codex detected that 192 rows could not
satisfy the frozen 1% tail-evidence rule; the human retained the threshold and directed the
1,056-row design. Focused macro tests replaced repeated certification-style full runs, while a
single final full suite was reserved for local release preparation.

Codex did not originate the RIEC-L1 research concept or its peer-reviewed methodological lineage.

## GPT-5.6 runtime role

GPT-5.6 operates after the deterministic decision. Through structured Responses API output it can
suggest column roles from a redacted profile, explain accepted aggregate evidence in a decision
memo, and review the memo for unsupported or prohibited claims. Deterministic validation has
precedence over model output. GPT cannot confirm the contract, select a candidate, calculate a
protocol, pass a gate, choose an action, or set a pilot range.

Fixture mode demonstrates the same structured stages without an API request. Live mode is
optional, server-configured, explicitly acknowledged by the user, and bounded to one successful
workflow per scenario per session.

## Public/private data boundary

The repository contains only deterministic public synthetic CSVs and aggregate recorded assets.
No private industrial row, private adapter, credential, personal identifier, publisher-formatted
asset, or historical archive is included. Raw rows, CSV contents, residual arrays, row
predictions, local paths, prompts, and credentials do not enter the GPT evidence context.

The synthetic mechanisms are demonstrations rather than calibrated process models. Their outputs
are retrospective screening references, not production setpoints, safety/compliance decisions,
causal findings, achieved savings, or evidence of external deployment.
