# Limitations update — which RC3 limitations are closed, narrowed, or still open (RC4 phase)

n = 5 deterministic repetitions per variant throughout; Wilson 95% intervals on every k/n, Clopper-Pearson one-sided
upper bound for k=0. Small n remains the headline statistical limitation.

| RC3 limitation | RC4 status | Note |
|---|---|---|
| SOURCE PRESERVATION partially verified (most `results/` had no baseline hash) | **Narrowed going forward** | `rc4/baseline/PRE_RC4_SHA256.txt` hashes 1895 files and re-verifies unchanged; does not retroactively cover the original 2026-10 runs. |
| DIAG-FIELDS NOT TESTED; B1/B4 INFERRED | **Closed for B4, narrowed for B1** | Measured (`rc4_p1_20261104T123454Z`): all 4 branch fields captured at the memfd execve; **B4 → VERIFIED** (argv0 bypass, default 0/5); **B1 → VERIFIED non-match** (memfd name is prefixed, so `proc.name` can't equal bare `runc`). B3 stays VERIFIED. |
| B2 INFERRED | **Still open (INCONCLUSIVE)** | Non-match re-confirmed (`pname=containerd-shim`), but the runc-**parent** positive case could not be produced on this VM (`exec -a runc` degraded to an ordinary `execve`). |
| R4 behaviour NOT TESTED | **Narrowed (PARTIAL)** | A fires (TP 5/5), B/D/E behave (silent); scenario **C (legit runc memfd clone) NOT REPRODUCIBLE** on runc 1.3.3, so R4 is explicitly **not** "validated". F/G BLOCKED. |
| E6-dynamic NOT TESTED | **Closed** | Measured: community rulesets add **0/19** direct detection, both conditions, with 945–969 FP/misattribution alerts. Static prediction CONFIRMED. |
| E8 independent variants NOT TESTED | **Closed** | Measured on independently-sourced variants (ART @ d0cc590b, event-generator v0.13.0): default **1/8**, v1 **5/8**. Kept separate from E4. |
| E9 Auditd proxy NOT TESTED | **Closed** | Measured: `subj=docker-default` proxy recall **0/25** under AppArmor unconfined vs 25/25 confined; PID/cgroup-lineage scope recovers all 25. Quantifies the proxy's AppArmor dependence. |
| E7 second sensor NOT TESTED | **Closed (with a model caveat)** | Measured: Tracee v0.23.2 **7/9** covered; Tetragon **base** sensor 0/4 — a model difference (no TracingPolicy), reported as such, not a head-to-head miss. Tracee v0.24.1 BLOCKED (glibc). |
| Repository requirement UNVERIFIED | **Unchanged** | No rubric in the workspace; no repository created; anonymous link stays "NOT AVAILABLE — PUBLICATION PENDING". |
| Verification scripts AI-written, not independently re-checked | **Partly mitigated** | Each experiment has an **independent recount** (`rc4/tools/recount_*.py`, separate code path) that reproduces the scorer headline (C4 PASS), plus a P1 scorer audit + unit test. Still AI-written, not third-party audited. |

## New limitations introduced this phase
- **n = 5** per variant: Wilson intervals are wide (e.g. E8 v1 5/8 → [0.31,0.86]). E5 (n≥15) was left optional and not run.
- **Single VM, single kernel/runtime** (kernel 6.8, Docker 28.4.0, runc 1.3.3): R4-C and some NT-B2/R4-F/G cases are
  not reproducible on this exact stack; results may differ on a runc build that memfd-clones.
- **E7 same-VM, sequential**: sensors were not run concurrently with Falco on separate hosts; timing/overlap effects
  are not characterised.
- **E7 Tetragon base-sensor only**: no TracingPolicy was authored, so Tetragon's 0/4 reflects the base model, not its
  full capability.
