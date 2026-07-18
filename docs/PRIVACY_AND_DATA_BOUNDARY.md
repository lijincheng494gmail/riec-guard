# Security and Data-Flow Threat Model

Version: `1.0.0`

## Assets

- uploaded public CSV;
- private local industrial rows;
- policy/SOP text;
- AuditContract and evidence ledger;
- OpenAI API key;
- generated report and audit bundle;
- Build Week repository integrity.

## Trust assumptions

- public users are untrusted;
- uploaded files and SOP text may be malicious;
- GPT output may be wrong or adversarially influenced;
- deterministic code and versioned configs are trusted only after tests and hashes;
- the hosted environment is not an approved private-data enclave.

## Primary threats and controls

| Threat | Control | Release test |
|---|---|---|
| private file auto-discovery | no private adapter/import/config in public build | external private file cannot change output |
| accidental Git leak | allowlist assembly + known-hash/identifier/secret scan | `public_release_scan` |
| path traversal | generated storage names; display name metadata only | malicious filename fixtures |
| oversized/resource-exhaustion upload | 10 MiB/100k row/100 column limits | boundary tests |
| malicious CSV payload/formula | parse as data only; no spreadsheet execution | formula-prefix fixtures |
| prompt injection in SOP | user-message boundary; structured extraction; read-only tools | injection golden tests |
| model invents policy/column | unresolved fields + deterministic profile cross-check + confirmation | fake-column test |
| raw private data leaves machine | payload builder denylist and integration capture | outbound-payload test |
| GPT invents numbers | placeholder binding + deterministic precheck | decoy/uncited number tests |
| claim overreach | fixed blockers + structured claim auditor | savings/compliance/setpoint cases |
| cross-run data access | run-scoped tool authorization | wrong-run ID test |
| persistent public data | ephemeral root + cleanup/janitor | retention test |
| secret leakage in telemetry | structured fields; no full prompt/raw row logs | log scan |
| denial by t-fit/bootstrap | fit timeout, replicate budget, scale limits | timeout/property tests |
| silent random-row fallback | exact splitter invariant and structured scale error | splitter tests |
| tampered audit bundle | artifact checksums + manifest | checksum mutation test |

## Residual risks

- a public user may still upload data they should not share;
- aggregate summaries can sometimes be sensitive;
- structured output reduces but does not eliminate prompt-injection risk;
- a synthetic benchmark cannot prove production safety;
- Streamlit/session cleanup depends on deployment lifecycle and must be tested;
- GPT semantic classification is fallible, so deterministic blockers remain authoritative.

## Hosted-mode hard blocks

- private industrial classification;
- local filesystem path input;
- remote URL ingestion;
- PDF/Office document parsing in P0;
- arbitrary external tools/connectors;
- database persistence;
- cross-session report retrieval;
- any output labelled compliance certificate, safe setpoint, or achieved savings.

## Release gate

Deployment is blocked unless:

- all security tests pass;
- OpenAI key is supplied only through secret management;
- no private modules/hashes/identifiers are present;
- clean-environment smoke audit passes;
- fallback labels appear correctly without an API key;
- audit bundle checksums validate.

## TASK-003 runtime settings boundary

The public runtime is public-first and immutable after construction. Public mode is the
default and does not require, discover, import, infer, or accept a private-data root. Hosted
mode rejects any private-mode configuration attempt.

Runtime artifacts use an ephemeral root outside the Git repository. If `RIEC_GUARD_EPHEMERAL_ROOT`
is omitted, the application uses an operating-system temporary directory. If it is set, the
configured root is normalized and rejected when it is the repository root or a repository
descendant.

When non-hosted private-local settings are explicitly constructed, the public ephemeral root
and private data root are normalized before comparison. They must be different, non-overlapping
roots; neither root may be an ancestor or descendant of the other.

Each run creates only this generated layout:

```text
<ephemeral_root>/<RUN-ID>/inputs/
<ephemeral_root>/<RUN-ID>/normalized/
<ephemeral_root>/<RUN-ID>/artifacts/
<ephemeral_root>/<RUN-ID>/telemetry/
```

`RUN-ID` and source storage names are generated internally. Original upload names remain display
metadata only and are never used as filesystem path fragments. Public-facing validation errors may
name the logical field or root role, but must not reveal resolved local paths.
