# Claim Auditor Specification

Version: `1.0.0`

## 1. Objective

The claim-auditing layer prevents a statistically generated screening result from becoming an unsupported business, legal, safety, or production claim.

It consists of:

1. deterministic claim extraction and prechecks;
2. GPT-5.6 structured semantic classification;
3. deterministic enforcement and rendering.

The second step is advisory within a fixed policy. It cannot override a deterministic block.

## 2. Material claim unit

A claim is a sentence or independent clause asserting one of:

- a numeric result;
- a selected model or protocol conclusion;
- process stability/instability;
- evidence sufficiency;
- an action or pilot reference;
- expected impact or savings;
- compliance, safety, optimality, causality, or deployment status;
- portability/generalization.

Each claim receives a stable `CLM-###` ID in document order.

## 3. Fixed classifications

### `supported`

All material elements are directly represented by cited evidence, and the sentence stays within:

- target product/scope;
- retrospective data;
- confirmed policy;
- protocol/gate status;
- screening—not production—language.

### `conditional`

The sentence is supportable only with one or more explicit qualifiers, such as:

- conditional on confirmed policy parameters;
- conditional on the selected/equivalent candidate set;
- conditional on bootstrap selection being frozen;
- retrospective screening only;
- synthetic benchmark only;
- requires controlled pilot validation.

### `unsupported`

No cited evidence establishes the assertion, or required evidence is absent.

### `overstated`

There is related evidence, but the claim increases certainty, scope, causality, generality, or operational force beyond the evidence.

### `prohibited`

The product boundary disallows the claim unless a separate external evidence class exists. The MVP has no such external evidence input, so these claims are blocked.

## 4. Deterministic prechecks

Before GPT audit, the application performs:

### 4.1 Evidence-ID check

- every cited ID exists in the current run ledger;
- no claim cites another run;
- evidence status is compatible with the claim;
- blocking evidence cannot be omitted from the executive summary.

### 4.2 Numeric-binding check

- all result numbers are placeholders before rendering;
- each placeholder has exactly one binding;
- binding evidence ID exists;
- JSON pointer resolves to a numeric/string value;
- format specification is allowed;
- no model-written arithmetic or alternate unit conversion;
- rendered number equals the bound value after declared formatting.

### 4.3 Banned/protected language check

Deterministically block phrases/patterns that assert:

- “will save”, “saved”, or achieved annual savings;
- “guarantees compliance”, “compliant”, or regulatory certification;
- “optimal setpoint”, “safe setpoint”, or direct instruction to alter production;
- “validated in production”, “deployed successfully”, or live causal effect;
- “proves” universal cross-domain validity;
- “zero underfill risk” or absolute safety;
- autonomous operation or replacement of engineering judgment.

Context-aware allowlist examples:

- “does **not** establish achieved savings”;
- “not a compliance certification”;
- “screening reference, not a production setpoint”.

### 4.4 State-language consistency

| Decision state | Allowed headline |
|---|---|
| `invalid_contract` | contract invalid; analysis not run/usable |
| `insufficient_evidence` | evidence insufficient for action |
| `no_actionable_headroom` | no positive screening headroom above threshold |
| `diagnose_process_first` | process/order diagnostics must precede pilot |
| `pilot_only_conservative` | conservative retrospective pilot reference, with conflicts/limits |
| `pilot_range_supported` | protocol-consistent retrospective screening reference, still requiring controlled validation |

A report cannot use a stronger state's language.

## 5. Evidence compatibility rules

### Numeric/statistical claim

Must cite the exact evidence item containing the value and unit.

### Model-selection claim

Must cite selection and candidate ledger evidence. For `near_tie`, the report must name the equivalence set rather than presenting one model as uniquely superior.

### Headroom claim

Must cite:

- protocol result;
- bootstrap result or explicit absence of uncertainty bound;
- action decision;
- relevant policy evidence.

### Stability claim

`G1` is a screening gate. Allowed:

- “screening rules flagged a material ordered pattern.”

Not allowed:

- “the process is statistically out of control” as a certification claim.

### Generalization claim

A synthetic mechanism result can support:

- “the method behaved differently under the tested heavy-tail world.”

It cannot support:

- “the system works for all particulate sauces.”

## 6. Required claim boundary

Every approved memo must contain a visible boundary stating, in substance:

- retrospective screening analysis;
- no autonomous control;
- no compliance certification;
- no achieved-savings evidence;
- no direct setpoint recommendation;
- controlled pilot and engineering review required.

The wording may vary, but the meaning and evidence IDs must remain.

## 7. GPT claim-auditor input

The auditor receives:

- deterministic precheck object;
- claim list;
- action decision;
- claim rules;
- only evidence items cited by the claims plus mandatory blocking evidence;
- no raw rows.

The auditor returns `CLAIM_AUDIT_SCHEMA.json`.

## 8. Enforcement

Export rules:

- any deterministic precheck failure -> free-form report blocked;
- any headline/material `prohibited` claim -> block;
- any unresolved `unsupported` or `overstated` headline/material claim -> block;
- `conditional` claim without required qualifier -> block;
- supporting claim errors may be auto-removed only if removal does not hide material limitations;
- approved replacement text must pass deterministic prechecks again.

The final rendered report is rehashed after edits.

## 9. Golden claim cases

| Claim | Expected |
|---|---|
| “The retrospective screening headroom is {{h}} [EV-…].” | conditional |
| “The factory can safely reduce fill by {{h}}.” | prohibited |
| “The analysis will save $2M per year.” | prohibited |
| “H2 and H3 differed by {{spread}} under the confirmed policy [EV-…].” | supported |
| “Page is the best model” when near tie exists | overstated |
| “Page and Weibull form the reported equivalence set [EV-…].” | supported |
| “The ordered screen flagged a change-point pattern [EV-…].” | supported/conditional |
| “The process is certified in control.” | prohibited |
| “The heavy-tail synthetic world caused parametric disagreement in this benchmark.” | supported |
| “RIEC Guard works across all industries.” | overstated/unsupported |

## 10. Audit outputs

The audit bundle includes:

```text
claim_map.json
claim_audit.json
report_draft.json
report.md
report.html
```

`claim_audit.json` records both deterministic and GPT modes. When GPT is unavailable, the deterministic template can still export, but it must identify the reduced audit mode.
