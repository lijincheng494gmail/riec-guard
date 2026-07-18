# Human Decision Log

This log records frozen decisions found in the dated Phase C/D planning baseline and Phase E task
protocol. It does not reconstruct informal conversations. The owner for every entry is the human
project director; Codex implements the consequences but does not originate or approve the decision.

## DEC-001 — Product identity and track

- **Date:** 2026-07-18 (frozen planning baseline)
- **Decision:** The product is named **RIEC Guard** and enters the **Work & Productivity** track.
- **Owner:** Human project director
- **Rationale:** The product serves quality, process, analytics, and operational-review workflows.
- **Frozen source/specification:** Phase C Project Charter §§1–3.
- **Implementation consequences:** Product naming, README, UI, submission, and evidence records use
  this identity and track consistently.
- **Status:** Frozen

## DEC-002 — Platform and first vertical

- **Date:** 2026-07-18 (frozen planning baseline)
- **Decision:** RIEC Guard is the platform; **Fill Pack** is its first complete vertical.
- **Owner:** Human project director
- **Rationale:** One coherent vertical is more testable and credible than multiple partial domains.
- **Frozen source/specification:** Phase C Project Charter §§1,7; Scope and Non-Goals §§1,3.
- **Implementation consequences:** P0 work completes one Fill workflow before any additional
  vertical or P1 expansion.
- **Status:** Frozen

## DEC-003 — RIEC-L0/L1/L2 separation

- **Date:** 2026-07-18 (frozen planning baseline)
- **Decision:** Separate contract/evidence boundary (L0), commensurable predictive selection (L1),
  and protocol/action/claim governance (L2).
- **Owner:** Human project director
- **Rationale:** Unlike evidence objects must retain distinct roles and provenance.
- **Frozen source/specification:** Phase D System Architecture §§1,4,7.
- **Implementation consequences:** Components and schemas may not collapse models, protocols,
  uncertainty, gates, policies, and claims into one score or service.
- **Status:** Frozen

## DEC-004 — Deterministic ownership of numbers

- **Date:** 2026-07-18 (frozen planning baseline)
- **Decision:** Deterministic code owns every numerical calculation and evidence value.
- **Owner:** Human project director
- **Rationale:** Statistics must be reproducible, testable, and traceable to evidence.
- **Frozen source/specification:** Phase C Project Charter §6; Phase D System Architecture §§1,7–9.
- **Implementation consequences:** GPT output cannot calculate, confirm, repair, or invent
  statistics; numeric results come from typed deterministic tools.
- **Status:** Frozen

## DEC-005 — Bounded GPT-5.6 roles

- **Date:** 2026-07-18 (frozen planning baseline)
- **Decision:** GPT-5.6 may compile contracts, draft evidence-linked memos, and audit claims only.
- **Owner:** Human project director
- **Rationale:** Language assistance is valuable while deterministic checks remain authoritative.
- **Frozen source/specification:** Phase C Project Charter §5; Phase D System Architecture §§8–9.
- **Implementation consequences:** GPT uses structured outputs/read-only evidence tools and cannot
  bypass validation, evidence binding, deterministic precheck, or final rendering.
- **Status:** Frozen

## DEC-006 — Physical public/private separation

- **Date:** 2026-07-18 (frozen planning baseline)
- **Decision:** Public synthetic demos and the private-local dairy anchor remain physically
  separated.
- **Owner:** Human project director
- **Rationale:** The hosted environment is not an approved private-data enclave.
- **Frozen source/specification:** Phase C Project Charter §§6,9; Scope and Non-Goals §§3–5; Phase D
  Security and Data-Flow Threat Model.
- **Implementation consequences:** The public build cannot discover, load, deploy, log, screenshot,
  or send private dairy rows to GPT; roots and release assembly remain disjoint.
- **Status:** Frozen

## DEC-007 — Deployment-group-aware evaluation

- **Date:** 2026-07-18 (frozen planning baseline)
- **Decision:** Predictive evaluation must hold out the declared future deployment unit.
- **Owner:** Human project director
- **Rationale:** Random-row evaluation can leak group structure and cannot support future-group
  claims.
- **Frozen source/specification:** Phase C Project Charter §§3,6; Phase D System Architecture §7.2.
- **Implementation consequences:** Exact leave-one-deployment-group-out is mandatory for the main
  claim; random rows are a labelled negative control only, never a fallback.
- **Status:** Frozen

## DEC-008 — Visible near ties and equivalence sets

- **Date:** 2026-07-18 (frozen planning baseline)
- **Decision:** Numerical near ties and equivalence sets must be shown rather than hidden.
- **Owner:** Human project director
- **Rationale:** A winner-only display overstates evidence when candidate scores are practically
  indistinguishable.
- **Frozen source/specification:** Phase C Project Charter §§3,5–7; Phase D System Architecture §7.2.
- **Implementation consequences:** Store raw winner, runner-up, gaps, tie thresholds, equivalence
  set, failures, and identifiable switchpoints.
- **Status:** Frozen

## DEC-009 — Downgrade/refuse instead of forced recommendation

- **Date:** 2026-07-18 (frozen planning baseline)
- **Decision:** Ordered action states downgrade or refuse action when evidence, stability, or
  headroom is insufficient.
- **Owner:** Human project director
- **Rationale:** An honest non-action state is safer than a fabricated production recommendation.
- **Frozen source/specification:** Phase C Project Charter §§3,6; Phase D System Architecture §§7.3–7.4.
- **Implementation consequences:** The first triggered state wins; invalid, insufficient,
  no-headroom, and diagnosis-first outcomes are successful bounded outputs, not errors to conceal.
- **Status:** Frozen

## DEC-010 — Screening references are not setpoints

- **Date:** 2026-07-18 (frozen planning baseline)
- **Decision:** Outputs are retrospective screening or pilot references, not production setpoints.
- **Owner:** Human project director
- **Rationale:** Controlled prospective validation and engineering review remain necessary.
- **Frozen source/specification:** Phase C Project Charter §§5–6; Scope and Non-Goals §§3,6.
- **Implementation consequences:** Reports use bounded conditional language and never present the
  action output as autonomous control, certification, or a direct operating instruction.
- **Status:** Frozen

## DEC-011 — Prohibited unsupported claims

- **Date:** 2026-07-18 (frozen planning baseline)
- **Decision:** Do not claim achieved savings, regulatory compliance, universal validity, causal
  effect, or successful live deployment without separate supporting evidence.
- **Owner:** Human project director
- **Rationale:** Public synthetic evidence and retrospective anchors do not establish those claims.
- **Frozen source/specification:** Phase C Project Charter §§6,9; Scope and Non-Goals §§3–6; Phase D
  Security and Data-Flow Threat Model.
- **Implementation consequences:** Deterministic blockers and the claim auditor reject or qualify
  unsupported language; GPT cannot override those blockers.
- **Status:** Frozen

## DEC-012 — One-task contracts and human gates

- **Date:** 2026-07-18 (frozen task-system baseline)
- **Decision:** Codex executes one formal task per user turn; the human project director reviews and
  accepts evidence before authorizing subsequent work or repair slots.
- **Owner:** Human project director
- **Rationale:** Small, auditable commits keep scope, evidence, safety, and repair decisions explicit.
- **Frozen source/specification:** Phase E Task Execution Protocol, Codex Main Thread Rules, and task
  contracts.
- **Implementation consequences:** Each task requires tests, an external execution report, one
  focused commit, and a stop; Codex cannot self-activate the next task or a repair slot.
- **Status:** Frozen
