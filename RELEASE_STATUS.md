> **RC4.1 update (2026-11-05).** The RC4 phase executed the items listed below as NOT TESTED: DIAG-FIELDS, NT-B1/B2/B4,
> R4-A/B/D/E, E6-dynamic, E7, E8, E9. Current statuses: P1 branch capture VERIFIED; NT-B4 VERIFIED (bypass);
> NT-B2 INCONCLUSIVE; R4 PARTIAL (R4-C NOT REPRODUCIBLE, R4-F/G BLOCKED); E6-dynamic VERIFIED (0/19); E7 MEASURED
> (Tracee 7/9; Tetragon base only); E8 MEASURED (5/8 vs 1/8); E9 PARTIAL. See report RC4.1 §9 and `07_RC4_EXTENSIONS/`.
> The RC3 text below is kept as the historical record.

# RELEASE_STATUS — Group 8 IAM302 Evidence Package (RC3)

Build 2026-11-04 (supersedes RC1 of 2026-11-03). Legend: **VERIFIED** (observed and checked in this project) ·
**PARTIAL** (partly verified; residual inference or missing direct capture) · **PLANNED** (designed, not executed) ·
**NOT TESTED** (not executed) · **PENDING CONFIRMATION** (needs a human) · **BLOCKED** (cannot be done here) ·
**HISTORICAL** (superseded content kept on purpose).

## 1. Milestones

| ID | Milestone | Status | Basis |
|---|---|---|---|
| M1 | Custom ruleset detects fileless-exec variants beyond default | **PARTIAL** | Strict-unseen P0 (primary): custom **1/4** [0.05, 0.70] vs default **0/4** [0.00, 0.49] (`02_P0_EVIDENCE/E4/e4_reclassified_subsets.csv`); E1 known variants: custom·first 8/11 direct (`e3_comparison.csv`). The intervals overlap; with 4 strict variants this does **not** establish generalisation. |
| M2 | Mechanism-family mapping | **VERIFIED** | `05_.../mechanism_families.csv` (7 families / 19 variants). |
| M3 | False-positive characterisation | **VERIFIED** | `02_P0_EVIDENCE/E2/e2_fp_summary.csv`; design-intended *build*/*python* rows labelled there. |
| M4 | Candidate mitigations for the memfd bypass (R1–R4) | **PLANNED** | `06_.../configs/rules/candidate_rules_v2.yaml`: syntax VERIFIED; **behaviour NOT TESTED**. |
| M5 | Community-ruleset dynamic evaluation and cross-tool comparison | **PLANNED** | Only the **static** E6 scan is done (§2). |

## 2. Experiments

E1–E5 are the core campaign; E6–E9 are extensions. E7–E9 definitions follow the canonical design
`05_METHODOLOGY_AND_TRACEABILITY/PLANNED_E7_E8_E9.md` and report Bảng 2 / §9. (RC1 of this file defined E7–E9
differently; that was wrong and is corrected here.)

| ID | What | Status | Notes |
|---|---|---|---|
| E1 | Detection across 11 E1 techniques, default vs custom | **VERIFIED** | Canonical runs shipped; `shm_ctr` = blocked, `procfd_link` = copy-up misattribution (non-findings). |
| E2 | False positives over benign workloads (+ E2-supp PostgreSQL/gcc) | **VERIFIED** | `e2_fp_summary.csv`. |
| E3 | Default-vs-custom comparison (first / all) | **VERIFIED** | Derived (`e3_comparison.csv`). |
| E4 | Held-out variants | **VERIFIED (reclassified)** | **PRIMARY strict-unseen: custom 1/4, default 0/4.** 2/5 = HISTORICAL-SENSITIVITY only. `e4_coverage.csv` / `e4_unseen_summary.csv` = HISTORICAL / PRE-P0. |
| E5 | Runtime/CPU overhead (none/falco/auditd/both) | **VERIFIED** | No runtime overhead distinguishable from run-to-run variation at n = 5 (not a claim of zero overhead); agent CPU ≈ 0.14 ms/exec (Falco), ≈ 0.16 ms/exec (Auditd). |
| E6-static | Community incubating/sandbox rulesets — static condition scan | **VERIFIED (static only)** | Rule counts from the pinned upstream files: sandbox 39, incubating 31, stable 25; scan re-run reproduces `e6_static_candidates.csv` byte-for-byte. Prediction only, not detection. Upstream tag commits not verifiable offline. |
| E6-dynamic | Run the community rulesets against the lab payloads | **NOT TESTED / PLANNED** | Needs sudo. |
| E7 | Cross-tool comparison: Tetragon, Tracee | **NOT TESTED / PLANNED** | No second sensor was run. |
| E8 | Independent variants: Atomic Red Team, falcosecurity/event-generator | **NOT TESTED / PLANNED** | No externally designed variant executed (`independent_external` = NOT TESTED). |
| E9 | Auditd container proxy: AppArmor default vs unconfined containers | **NOT TESTED / PLANNED** | Prediction from code only; no unconfined run. |

## 3. P1 — DEV-T1r memfd bypass

| Item | Status | Evidence |
|---|---|---|
| DEV-T1r false negative on default ruleset | **VERIFIED** | default raw = 0 bytes (no alert), 5/5 payload ok |
| Custom ruleset direct detection of DEV-T1r | **VERIFIED** | custom raw: 5/5 `LAB memfd exec masquerading as runc clone` |
| B3 `proc.exepath` match | **VERIFIED** — sole directly verified matching branch | `proc.exepath = memfd:runc_cloned:/proc/self/exe` captured |
| B2 `proc.pname` non-match | **VERIFIED** (directly captured) | `proc.pname = containerd-shim` |
| B1 `proc.name` non-match | **PARTIAL (INFERRED)** | `proc.name` not in the event's output_fields |
| B4 `proc.exe` non-match | **PARTIAL** (field semantics verified; DEV value inferred) | `03_P1_EVIDENCE/field_semantics/` |
| DIAG-FIELDS | **NOT TESTED** | rule ready, not loaded |
| R4 behaviour (A/B/D/E) | **NOT TESTED** | syntax VERIFIED only |
| R4 scenario C (real runc memfd clone) | **BLOCKED (NOT REPRODUCIBLE)** | runc 1.3.3 does not memfd-clone on this VM |

## 4. AI usage & team

| Item | Status |
|---|---|
| Author / contribution identity | **Group 8** (owner decision 2026-11-04); group-level declaration and contribution overview |
| Individual declarations, allocations, confirmation tables | **NOT PART OF RC3** (owner decision); superseded records kept in repo `docs/historical/` only |
| Course code | **IAM302** (owner-confirmed 2026-11-04) |
| Group 8 AI audit (AL-01..AL-28; corrections H-01..H-07 in sheet "AI Corrections"; decisions DL-1..DL-7) | **VERIFIED artifacts**; content RETROSPECTIVE-RECONSTRUCTION; ChatGPT use group-reported |

## 5. Statistical limitations (apply to every rate here)
- Unit of analysis = **variant**, not the population of fileless techniques; results describe the tested variants on
  one VM / one runtime (Docker + runc 1.3.3) and are not generalised beyond them.
- **n = 5 repetitions per variant** (deterministic repeats, not independent samples). Per-run intervals are
  REFERENCE_ONLY.
- Proportions carry **95% Wilson** intervals; they are wide (e.g. 1/4 → [0.05, 0.70]). Zero cells also get a one-sided
  95% upper bound (0/4 → 0.527).
- `falco -V` proves syntax only.

## 6. Integrity and preservation
- `SHA256SUMS.txt` covers every file except itself; `build_release_candidate.py verify` re-checks every copy against
  its repo source.
- **SOURCE PRESERVATION: PARTIALLY VERIFIED.** Raw evidence (`results/`, `analysis/`) was unchanged by the 2026-11-04
  remediation (checked against a hash snapshot taken at its start), and 52 `results/` files plus other evidence match
  the pre-existing 2026-10-29 baseline (`final_evidence_report/verification/EVIDENCE_SOURCE_SHA256.txt`). The remaining
  `results/` files have **no pre-existing baseline hash**; their preservation since the experiments is supported by
  mtimes and root ownership but not proven. No retrospective baseline has been presented as a pre-experiment record.

## 7. Overall verdict
See `07_REVIEW_CHECKLIST/submission_readiness.md`.
