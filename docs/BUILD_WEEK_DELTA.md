# Build Week Delta

## 1. Evaluation boundary

The entrant is submitting an **existing research foundation with a substantial new productization layer**. Judges should be able to distinguish the two without inference.

### Before the submission period

- RIEC-L1 mathematical method and Array paper;
- Project 2 minimal runtime and three cases;
- private dairy analysis/manuscript;
- the RIEC-Fill starter script/demo;
- prior protocol-governance and claim-guardrail ideas.

### New/meaningfully extended during Build Week

| Subsystem | Build Week delta | Evidence required |
|---|---|---|
| Repository | clean public/private architecture, licensing, release allowlist | first commit, tree, release scan |
| Contract layer | typed AuditContract, validation, user confirmation | schema, tests, UI recording |
| RIEC engine | complete ledger, row-weighted grouped risk, tie/equivalence, switchpoints | code, golden tests, dated commits |
| Fill adapter | schema mapping, group/order rules, headroom protocol registry | tests and public fixtures |
| Benchmark | mechanism-based generator, oracle headroom, split/guardrail ablations | generator commits, manifests, plots |
| GPT-5.6 | contract compiler, controlled tool use, evidence-linked memo, claim audit | model logs, request IDs, demo video |
| Product | complete web flow, export, error/fallback states | deployment URL, screenshots, test account if needed |
| Quality | unit/integration/release tests, provenance, checksums | CI/test report |
| Submission | README, Codex collaboration narrative, video, judging instructions | final repository and Devpost fields |

## 2. Minimum meaningful extension

The delta is not considered sufficient unless all of the following are true:

1. GPT-5.6 is visible in a core runtime workflow, not only in documentation.
2. The main Codex session contains the majority of core implementation work.
3. A public judge can run the new UI and evidence bundle without the private starter workspace.
4. The new engine fixes the row-bootstrap, order, zero-headroom, hard-coded-policy, and incomplete-RIEC blockers.
5. At least one mechanism demonstrates that grouped and random-row conclusions differ.
6. At least one report claim is prevented or downgraded by the new claim-auditor layer.
7. Prior and new work are documented file-by-file or subsystem-by-subsystem.

## 3. Evidence-capture protocol

For every major task/commit, record:

```text
timestamp
Codex thread/session
objective
files changed
key human decision
Codex contribution
tests run
result/blocker
commit SHA
```

Additional evidence:

- run `/feedback` in the main Codex project thread after core integration;
- retain timestamped session logs/screenshots where permitted;
- keep dated commit history and tagged submission version;
- include a short architecture timeline in README;
- record GPT-5.6 model name/request metadata in public demo manifests, redacting secrets.

## 4. Demo wording

Recommended:

> RIEC-L1 was the peer-reviewed research foundation. During Build Week, I used Codex and GPT-5.6 to reimplement its full audit contract, create a group-aware Fill Pack, build mechanism benchmarks and claim guardrails, and ship a working web product.

Avoid:

> I built RIEC-L1 and the entire project in four days.

## 5. Submission checklist tied to the delta

- repository license and relevant attributions;
- English README and testing instructions;
- prior/new work section near the top of README;
- Codex collaboration section with key decisions, not a generic AI acknowledgment;
- `/feedback` Session ID;
- public deployment or test build;
- video under three minutes showing both the product and how GPT-5.6/Codex were used;
- no private or publisher material in the repository/video.
