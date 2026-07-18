# User Flow and Screen Specification

Version: `1.0.0`  
UI: thin Streamlit application  
Primary demo length: under three minutes

## 1. Product principle

The UI makes the evidence boundary visible. It must not look like a chatbot that invents a recommendation. The user sees:

```text
input -> confirmed contract -> deterministic evidence
-> conflicts/gates -> bounded action -> audited memo
```

A judge can finish the built-in scenario without credentials, code changes, or rebuilding.

## 2. Global UI rules

Persistent header:

```text
RIEC Guard — Fill Pack
Retrospective screening; not autonomous control or compliance certification.
```

Persistent run status:

```text
Source
Contract
RIEC-L1
Protocols
Action
Memo
```

Every result card shows:

- status;
- evidence ID link;
- method/version;
- scope;
- warning/claim boundary.

Do not use green “safe” language. Suggested labels:

```text
supported
conditional
conflict
insufficient
diagnose first
blocked
```

## 3. Screen 1 — Source

### Goal

Choose a built-in mechanism or upload a demo-safe CSV.

### Controls

- built-in scenario cards:
  - Stable symmetric
  - Foaming / left-skew
  - Heavy-tail / particulate
  - Multimodal streams
  - Batch drift
  - Autocorrelated viscous
- CSV uploader;
- public-data warning;
- optional download of sample schema.

### Validation

Display file size, rows, columns, and hash. Reject unsupported/oversize files with a structured error.

### Exit

`Profile source`

## 4. Screen 2 — Profile and policy

### Dataset profile panel

- column names/types;
- missingness;
- unique counts;
- suggested semantic roles;
- no raw full-table preview in private mode.

### Policy input tabs

1. structured form;
2. paste short SOP text (max 20,000 characters);
3. `.txt` upload (max 100 KiB).

P0 form fields:

- nominal quantity;
- unit;
- lower limit;
- alpha;
- minimum actionable shift;
- maximum screening shift;
- deployment group;
- time order;
- stream/product/shift mappings;
- protocol spread tolerance.

### Exit

`Compile draft contract with GPT-5.6` or `Continue with manual form`.

The UI must label which path was used.

## 5. Screen 3 — Contract review and confirmation

Render each decision-critical field as:

```text
value
source
confidence
validation status
confirmation checkbox/control
```

Blocking unresolved items appear first. The user cannot start analysis until all blocking items are resolved.

Required visible statement:

> GPT-5.6 proposed this contract; deterministic validation and your confirmation define the analysis.

Any edit creates a new draft/hash.

### Exit

`Confirm and run audit`

## 6. Screen 4 — Audit progress

Show deterministic stages:

```text
Normalize
Validate groups
Evaluate finite candidates
Compute RIEC selection
Run headroom protocols
Run group bootstrap
Run ordered screen
Resolve action
Finalize evidence ledger
```

Show GPT stages separately:

```text
Contract compiler: complete/manual/fallback
Memo composer: pending
Claim auditor: pending
```

Do not imply GPT performed the statistical analysis.

On a protocol failure, continue only when the typed pipeline allows it; show ineligible/failed status rather than hiding the protocol.

## 7. Screen 5 — Decision and conflict

### Top card

One of six states with plain-language explanation.

Example:

```text
PILOT ONLY — CONSERVATIVE
The retrospective protocols support a positive screening reference,
but material protocol spread requires a narrower pilot and explicit review.
```

### Panels

- safe headroom basis;
- pilot reference, if allowed;
- RIEC winner/equivalence set;
- score gap/near tie;
- protocol estimates and uncertainty bounds;
- protocol spread against tolerance;
- stability/evidence gates;
- “what this does not mean.”

All values link to evidence IDs.

## 8. Screen 6 — Evidence explorer

Tabs:

### RIEC candidate ledger

- candidate status;
- parameter count;
- `BIC_eff`;
- grouped risk;
- group-balanced diagnostic;
- `XPE`;
- `C_lambda`;
- winner/near tie.

### Switching boundaries

Pairwise table/plot showing where identifiable score changes occur as `c` changes.

### Protocol ledger

H1/H2/H3/U1/G1/G2 statuses, values, diagnostics, warnings.

### Grouping audit

- number and sizes of deployment groups;
- fold coverage;
- explicit statement that random-row fallback was not used.

### Evidence graph

Selected evidence item, parents, source artifacts, hashes, and version.

## 9. Screen 7 — Memo and claim audit

Actions:

1. `Draft memo with GPT-5.6`;
2. show structured draft status;
3. run deterministic precheck;
4. `Audit claims with GPT-5.6`;
5. show claim classifications and required edits;
6. render approved Markdown/HTML.

When API is unavailable:

- show deterministic memo template;
- show fallback label;
- do not claim the GPT stage completed.

Blocked claims are visible with reason codes. The user cannot export an unapproved free-form draft.

## 10. Screen 8 — Export

Download:

- `audit_bundle.zip`;
- report Markdown;
- report HTML;
- optional public-safe charts.

Display bundle contents and SHA-256 checksum.

Before download, show:

```text
Source classification
GPT fallback status
Claim-audit mode
Release scan status
Run ID
```

## 11. Demo-safe default story

Recommended recorded flow:

1. choose `heavy_tail_particulate`;
2. display a seemingly positive mean-overfill diagnostic;
3. confirm built-in policy and grouped deployment unit;
4. run RIEC/protocol audit;
5. reveal disagreement between empirical and parametric protocols;
6. show a near-tie/equivalence or material diagnostic;
7. action downgrades to `pilot_only_conservative` or `diagnose_process_first`;
8. GPT memo cites evidence;
9. claim auditor blocks “will save $X”;
10. export bundle.

This showcases the core idea: disagreement is not hidden, and AI is constrained by evidence.

## 12. Accessibility and language

- English is the public submission default;
- no critical status conveyed by color alone;
- tables downloadable as CSV;
- compact mobile fallback, but desktop is the judged target;
- charts include titles, units, scope, and textual interpretation;
- all warnings can be read without hover;
- no copyrighted music or third-party trademark dependence in demo assets.
