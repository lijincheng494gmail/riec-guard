# RIEC-L1 Method Specification for RIEC Guard

Status: normative implementation specification derived from the published RIEC-L1 paper and checked against the current Project 2 runtime.  
Prior-work DOI: `10.1016/j.array.2026.101097`  
Purpose: prevent Codex from inferring the method from prose or from copying an incomplete legacy implementation.

## 1. What RIEC-L1 is

RIEC-L1 is a **declared choice map over a finite, reviewable candidate library**. It does not invent a new predictive-risk estimator or a new information criterion. It converts a descriptive evidence ledger into a reproducible conditional recommendation under an explicit decision context.

The method requires both:

1. an evidence ledger containing structural and deployment-aligned predictive signals for every candidate; and
2. a predeclared operation explaining how disagreement among those signals is resolved.

RIEC-L1 is not a p-value, probability that a model is true, Bayes factor, universal selection rule, or proof of predictive superiority.

## 2. Core objects

### 2.1 Evidence object

Let

\[
D=\{(x_i,y_i,g_i)\}_{i=1}^{n}
\]

where `g_i` identifies the operational deployment unit: batch, run, condition, material, nozzle stream, or another unit that will be unseen at deployment.

Every run must tag its evidence class:

- `empirical`: observed grouped evidence;
- `deterministic_audit_path`: a controlled transformation used to trace a decision boundary;
- `synthetic_benchmark`: generated data used to test behavior.

These classes must not be pooled or described as interchangeable evidence.

### 2.2 Finite candidate library

\[
\mathcal{M}=\{M_1,\ldots,M_J\}
\]

Each candidate has:

- stable `candidate_id`;
- structural family `C`;
- complexity level `f`;
- fitted-parameter count `k_M`;
- deterministic factory/tool entry point;
- feasibility and failure rules.

The library is frozen before inspecting the final ranking.

### 2.3 Decision context

\[
\theta=(G,M_0,\ell,A,n_{eff},c,\lambda_n,T)
\]

where:

- `G`: grouping and split rule;
- `M0`: baseline candidate;
- `ell`: held-out loss;
- `A`: risk aggregation rule;
- `n_eff`: declared penalty-calibration scalar;
- `c`: predictive trade-off constant;
- `lambda_n = c/log(n_eff)`;
- `T`: predeclared tie/equivalence policy.

The published paper uses `n_eff = n` as a visible row-count penalty calibration and audits reductions of that count. It does **not** validate `n_eff` as the number of independent groups. RIEC Guard must preserve that wording unless a new group-scale likelihood is separately justified.

## 3. Deployment-aligned grouped risk

For candidate `M`, fit on all groups except held-out group `g`, producing `f_{M,-g}`. The published default is the point-weighted held-out mean squared error:

\[
E_{CV}(M)=\frac{1}{n}\sum_g\sum_{i:g_i=g}\left[y_i-f_{M,-g}(x_i)\right]^2.
\]

The current Project 2 runtime instead computes the **unweighted mean of fold MSE values**. Those coincide when held-out groups have equal sizes, as in the current three examples, but can differ for unequal groups. The new engine must:

- make `risk_aggregation` explicit;
- use `row_weighted` as the published-compatible default;
- optionally report `group_balanced` as a separate diagnostic, not silently substitute it.

Random-row CV may be run only as a labelled negative control.

## 4. Structural comparison signals

For full-data residual sum of squares `SSE_M`, parameter count `k_M`, and row count `n`:

\[
AIC(M)=n\log(SSE_M/n)+2k_M,
\]

\[
AICc(M)=AIC(M)+\frac{2k_M(k_M+1)}{n-k_M-1},\quad n>k_M+1,
\]

\[
BIC_{eff}(M)=n_{eff}\log(SSE_M/n_{eff})+k_M\log(n_{eff}).
\]

These are pseudo-likelihood-style comparison signals under the paper's stated limitations. `BIC_eff` is the structural coordinate used by RIEC-L1; AIC and AICc remain reference columns.

Required implementation behavior:

- use the same SSE convention across candidates;
- record failed fits rather than dropping them;
- never mix a group-level count with a point-level SSE without a separately defined group-level likelihood;
- retain raw precision in machine outputs.

## 5. Baseline-normalized predictive gain

For declared baseline `M0`:

\[
XPE(M)=\frac{E_{CV}(M_0)}{E_{CV}(M)}.
\]

`XPE > 1` means lower grouped risk than the baseline. It is a relative engineering coordinate, not an effect probability. All risks must be positive and finite; numerical clipping, if used, must be recorded in the ledger.

## 6. RIEC-L1 score and recommendation

\[
\lambda_n=\frac{c}{\log(n_{eff})},
\]

\[
C_{\lambda}(M)=BIC_{eff}(M)-\lambda_n\log XPE(M),
\]

\[
M_{RIEC}=\arg\min_{M\in\mathcal{M}}C_{\lambda}(M).
\]

Lower is better. The default `c=1` in the published examples is declared, conservative, and BIC-anchored. It is not oracle-derived or universal.

## 7. Audit diagnostics

### 7.1 Candidate score gap

\[
G_{\theta}(M)=C_{\lambda}(M)-C_{\lambda}(M_{RIEC})\ge 0.
\]

### 7.2 Runner-up margin

\[
G_{\theta}^{*}=\min_{M\ne M_{RIEC}}G_{\theta}(M).
\]

This is a deterministic score separation, not a confidence interval.

The stored cases illustrate why it matters:

- optics runner-up margin: about `558.463`;
- RTD runner-up margin: about `319.727`;
- drying Page/Weibull margin: about `7.25e-8`, effectively a numerical near-tie requiring equivalence-aware language.

### 7.3 Pairwise switching boundary

For candidates `A` and `B`:

\[
C_{\lambda}(B)-C_{\lambda}(A)
=\Delta_{BIC}(A,B)-\lambda_n\log\frac{E_{CV}(A)}{E_{CV}(B)}.
\]

`B` outranks `A` when:

\[
\Delta_{BIC}(A,B)<\lambda_n\log\frac{E_{CV}(A)}{E_{CV}(B)}.
\]

Under `lambda_n=c/log(n_eff)` and a non-zero log-risk ratio:

\[
c^{*}(A,B)=\frac{\Delta_{BIC}(A,B)\log(n_{eff})}
{\log(E_{CV}(A)/E_{CV}(B))}.
\]

For the stored drying Page-versus-Midilli ledger, the reconstructed switchpoint is approximately `c*=562.15`; the default `c=1` is therefore strongly on the compact-model side of that comparison.

## 8. Tie and equivalence policy

The paper requires tie handling to be declared in advance but the minimal runtime does not implement a tolerance. RIEC Guard must add an explicit implementation policy:

- store the raw numeric winner;
- define absolute and relative score tolerances before evaluation;
- if multiple candidates fall inside tolerance, return an `equivalence_set` and a deterministic secondary ordering for display only;
- label a tiny runner-up margin as `near_tie`, not as decisive superiority;
- preserve family-level equivalence when implementations are numerically indistinguishable.

This policy is an engineering implementation requirement, not a change to the published score formula.

## 9. Required evidence ledger

Each candidate row must contain at least:

```text
candidate_id
family_C
complexity_f
k_params
fit_status
failure_reason
SSE
AIC
AICc
BIC_eff
E_CV_row_weighted
E_CV_group_balanced   (optional diagnostic)
XPE
c
lambda
C_lambda
score_gap
rank
near_tie
fold_count
group_count
evidence_id
```

The run-level bundle must contain:

```text
decision_context.json
candidate_ledger.csv
fold_metrics.csv
selection.json
pairwise_switches.csv
run_manifest.json
claim_boundary.json
artifact_checksums.txt
```

## 10. Invariants and failure states

The engine must stop or downgrade when:

- fewer than two valid deployment groups exist;
- the baseline is missing or infeasible;
- a candidate risk is non-finite/non-positive after declared handling;
- `n_eff <= 1`, making the schedule undefined or unstable;
- the candidate library changes after ranking begins;
- fit failures leave no feasible candidate;
- group overlap exists between training and test;
- evidence class or provenance is missing.

Fit failures remain visible in the ledger.

## 11. Current code compatibility

| Capability | Published method | Project 2 minimal runtime | Directive |
|---|---|---|---|
| grouped split | yes | yes | retain, add overlap assertions |
| BIC_eff | yes | yes | retain with semantic clarification |
| XPE and C_lambda | yes | yes | retain |
| AIC/AICc/SSE in ledger | yes | no | implement |
| gaps and runner-up margin | yes | no | implement |
| pairwise switches | yes | no | implement |
| explicit evidence class | yes | no | implement |
| explicit tie tolerance | required policy | no | implement |
| published risk aggregation | point-weighted | equal-fold mean | correct and expose both |

## 12. Interpretation boundary

The final recommendation must be written as:

> Under the declared candidate library, grouping, baseline, penalty calibration, schedule, and tie policy, candidate X is the conditional RIEC-L1 recommendation; the runner-up margin and switching diagnostics are shown for audit.

It must not be written as proof that candidate X is true, universally optimal, statistically superior, or externally validated.
