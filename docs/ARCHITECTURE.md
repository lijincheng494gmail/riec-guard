# RIEC Guard — Phase D System Architecture

Status: architecture baseline for Codex task generation  
Product: **RIEC Guard — Fill Pack**  
Track: **Work & Productivity**  
Architecture version: `1.0.0`

## 1. Architectural intent

RIEC Guard turns a production-data file and an operating-policy description into an auditable, claim-bounded screening memo. It is intentionally split into three logical layers:

1. **RIEC-L0 — contract and evidence boundary**
   - profile a dataset without exposing raw rows to the language model;
   - map uploaded columns to semantic roles;
   - compile and validate an `AuditContract`;
   - require confirmation of decision-critical fields.

2. **RIEC-L1 — commensurable predictive candidate selection**
   - evaluate one finite, versioned structural candidate library;
   - use leave-one-deployment-group-out prediction;
   - compute published-compatible row-weighted grouped risk;
   - compute `BIC_eff`, baseline-normalized `XPE`, `C_lambda`, winner, runner-up, near ties, equivalence sets, and switching boundaries.

3. **RIEC-L2 — protocol, action, and claim governance**
   - run typed headroom protocols, uncertainty procedures, and screening gates;
   - resolve conflicts without pretending unlike evidence objects are one score;
   - produce one mutually exclusive action state;
   - generate an evidence-linked memo and audit its claims.

The numerical owner is always deterministic Python code. GPT-5.6 Sol is the language and orchestration layer, not the source of statistical values.

## 2. Deployment profile

### 2.1 Public Build Week product

- Python 3.12 package.
- Thin Streamlit web interface.
- Shared application service used by the UI, CLI, tests, and benchmark scripts.
- Ephemeral, run-scoped storage.
- Public synthetic scenarios and demo-safe CSV uploads only.
- No login, multi-tenant database, background queue, or production control integration.
- OpenAI Responses API calls are stateless and use `store=false`.

### 2.2 Local private research mode

A separate, non-deployable adapter may analyze private industrial data on the user's machine. It has a physically separate input, cache, log, and artifact root. Private mode is not imported by, discoverable from, or configurable in the public deployment.

The public application must remain identical whether private files exist elsewhere on disk.

## 3. Trust zones

```text
ZONE A — Browser / untrusted input
  CSV, short SOP text, structured form values
             |
             v
ZONE B — Public deterministic application
  upload guard -> profiler -> contract validator
  -> RIEC engine -> protocols/gates -> action engine
  -> evidence ledger -> deterministic renderer
             |
             | redacted schemas, summaries, evidence objects only
             v
ZONE C — OpenAI API
  contract compiler / memo composer / claim auditor
             |
             v
ZONE D — Run-scoped public artifacts
  synthetic/public-upload audit bundle, then deletion
```

A separate `ZONE P — local private workspace` exists outside the public repository and deployment. Raw private rows may never cross into Zone C by default.

## 4. Component boundaries

| Component | Owns | Must not own |
|---|---|---|
| `UploadGuard` | file type, byte/row/column limits, encoding, filename sanitization | semantic inference |
| `DatasetProfiler` | deterministic types, missingness, counts, safe summaries, redacted mapping hints | policy values, decisions |
| `ContractCompiler` | GPT/manual conversion of profile + policy context to draft typed contract | statistical calculation |
| `ContractValidator` | schema, units, grouping, order, policy consistency, blocking/warning errors | silently filling unresolved values |
| `CandidateRegistry` | finite, versioned model declarations | dynamic model search |
| `RiecSelector` | fits/evaluates candidates and emits RIEC-L1 ledger | action recommendations |
| `ProtocolEngine` | H1/H2/H3/U1/G1/G2 typed outputs | treating gates or bootstrap as model candidates |
| `ActionEngine` | ordered state machine and pilot-reference screening range | production setpoint or compliance certification |
| `EvidenceLedger` | immutable evidence IDs, provenance, dependencies, artifact references | prose-only findings |
| `MemoComposer` | evidence-bound report draft | new numbers or uncited claims |
| `ClaimPrecheck` | deterministic numeric/evidence/phrase checks | semantic judgment beyond fixed rules |
| `ClaimAuditor` | structured claim classification and required edits | overriding deterministic blockers |
| `AuditBundleExporter` | self-contained files and checksums | exporting blocked free-form reports |
| `RunManifestWriter` | code, environment, input, model, seed, fallback, artifact provenance | prompts or secrets marked confidential |

## 5. End-to-end sequence

```text
1. Source selection
   built-in mechanism OR public CSV upload

2. Deterministic profile
   schema, counts, safe examples, mapping candidates

3. Policy capture
   structured form OR pasted text OR .txt file

4. Contract compilation
   GPT-5.6 Structured Output, manual form, or versioned built-in contract

5. Deterministic validation and user confirmation
   blocking fields cannot remain unresolved

6. Data normalization
   typed quantity, product, group, time, stream, shift;
   optional explicit mass/volume conversion

7. RIEC-L1 selection
   exact LOGO folds -> candidate ledger -> equivalence set -> switchpoints

8. RIEC-L2 protocols and gates
   H1/H2/H3 -> U1 -> G1/G2

9. Action decision
   exactly one state, reason codes, claim boundary

10. Evidence ledger finalization
    canonical hashes and immutable evidence IDs

11. Memo composition
    read-only evidence tools; numeric placeholders only

12. Deterministic report precheck
    numeric binding, evidence existence, prohibited claim rules

13. GPT-5.6 claim audit
    structured classifications and replacement language

14. Deterministic render and export
    Markdown/HTML + complete audit bundle + checksums
```

No GPT-generated output may bypass steps 5, 10, 12, or 14.

## 6. Shared application service

The UI and CLI call one service boundary:

```python
class AuditService:
    def profile_source(source: SourceSpec) -> DatasetProfile: ...
    def compile_contract(context: ContractCompileContext) -> AuditContractDraft: ...
    def validate_contract(contract: AuditContract) -> ValidationReport: ...
    def confirm_contract(contract: AuditContract) -> AuditContract: ...
    def run_audit(contract: AuditContract, source: SourceSpec) -> AuditResult: ...
    def compose_memo(run_id: str) -> ReportDraft: ...
    def audit_claims(run_id: str, draft: ReportDraft) -> ClaimAudit: ...
    def export_bundle(run_id: str) -> Path: ...
```

`run_audit` is an orchestrator over deterministic services. It does not contain statistical formulas itself. CLI, UI, tests, and benchmark code all import this service.

## 7. Deterministic analysis pipeline

### 7.1 Normalized domain table

Internal canonical fields:

```text
row_id
quantity
product
deployment_group
time
stream
shift
source_row_number
```

Optional fields:

```text
weight
density
tare
```

Every normalized row retains a source-row locator locally. The locator is never sent to GPT.

### 7.2 RIEC-L1

- Splitter: exact leave-one-deployment-group-out.
- Default limit: at most 200 deployment groups for the public MVP.
- Primary risk: sum of held-out squared errors divided by total held-out rows.
- Secondary diagnostic: mean of group-specific MSEs.
- Baseline: `M0_intercept`.
- Candidate set: frozen registry, no dynamic search.
- Score:
  - effective information criterion from the full-data fit;
  - baseline-normalized predictive term;
  - `C_lambda` using contract value `c`.
- Output:
  - feasibility/failure per candidate;
  - raw numeric winner and runner-up;
  - absolute score gap;
  - near-tie/equivalence set;
  - pairwise switching values where identifiable.

If exact group evaluation exceeds the declared scale limit, the service returns a structured `scale_limit` error. It must not silently fall back to random rows.

### 7.3 Headroom protocols

- `H1`: exact finite-sample empirical boundary under a strict `< lower_limit` underfill event.
- `H2`: Gaussian residual-tail model using cross-fitted predictions from the selected equivalence set.
- `H3`: Student-t residual-tail model with bounded degrees of freedom and fit timeout.
- `U1`: whole-group bootstrap, conditional on the main selection.
- `G1`: ordered stability screening only when order is confirmed.
- `G2`: explicit evidence sufficiency.

### 7.4 Action state machine

Evaluation order is fixed:

```text
invalid contract
-> insufficient evidence
-> no actionable headroom
-> diagnose process first
-> pilot only conservative
-> pilot range supported
```

The first triggered state wins. The state machine is pure and deterministic.

## 8. GPT-5.6 runtime

Three calls are permitted:

1. `contract_compile`
2. `memo_draft`
3. `claim_audit`

Model configuration:

```text
model: gpt-5.6-sol
API: Responses
store: false
```

The product runtime exposes only read-only application functions to the memo composer:

- `get_contract_summary`
- `get_selection_summary`
- `get_protocol_results`
- `get_action_decision`
- `get_evidence_items`
- `get_claim_rules`

No shell, browser, code interpreter, MCP, database write, filesystem write, or direct statistical-computation tool is available to the model.

## 9. Report integrity

GPT produces templates such as:

```text
The screening headroom is {{safe_headroom}} [EV-ACTION-...].
```

A deterministic binding table maps each placeholder to one evidence item and JSON pointer. The renderer inserts formatted values. Any uncited number, unknown evidence ID, mismatched binding, or prohibited statement blocks free-form export.

A deterministic report template remains available when API access fails.

## 10. Persistence and cleanup

Public mode creates:

```text
<ephemeral_root>/<run_id>/
  inputs/
  normalized/
  artifacts/
  telemetry/
```

Rules:

- filenames are replaced with generated artifact IDs;
- original display names are metadata only;
- paths cannot contain user-controlled traversal;
- uploaded bytes and derived row-level files are removed at session/run expiry;
- audit bundles are created on demand;
- no shared database or cross-user cache;
- logs contain hashes, counts, status, timing, and error classes—not raw rows or full SOP text.

## 11. Failure semantics

Every recoverable or terminal failure returns `ERROR_ENVELOPE_SCHEMA.json`.

Examples:

- malformed file -> structured upload error;
- missing group -> blocking contract error;
- >200 groups -> explicit scale error;
- parametric fit timeout -> protocol ineligible, not fabricated result;
- API unavailable -> labelled manual/template fallback;
- claim audit unavailable -> free-form GPT memo blocked; deterministic memo can still export with warning;
- release scan failure -> export/deployment blocked.

## 12. Required audit bundle

```text
audit_contract.json
candidate_registry.json
candidate_ledger.csv
fold_metrics.csv
selection.json
pairwise_switches.csv
protocol_results.json
action_decision.json
evidence_ledger.json
claim_map.json
claim_audit.json
report.md
report.html
run_manifest.json
artifact_checksums.sha256
```

PDF is optional and outside P0.

## 13. Requirement traceability

Every Phase C P0 requirement is mapped in `ARCHITECTURE_REQUIREMENTS_TRACEABILITY.csv`. The architecture exit gate requires:

- all P0 rows mapped to a component, schema, and future test;
- all supplied JSON examples validate;
- the GPT/numeric boundary is explicit;
- no public component can discover a private path;
- one public built-in scenario runs end to end from a clean environment;
- deterministic and GPT fallback labels are preserved in the manifest.

## 14. Architecture non-goals

The MVP is not:

- closed-loop control;
- a production setpoint optimizer;
- regulatory certification;
- a general-purpose AutoML system;
- a multi-tenant SaaS;
- a repository for private industrial data;
- evidence of achieved material savings;
- a replacement for engineering review or controlled pilots.
