# DEV-T1r + R4 reproduction (P1.6, 2026-11-03)

Three levels. Levels 1–2 need no privileges and reproduce the **existing** result from shipped data. Level 3 is the **new** privileged testing (R4 behaviour and the untested exception branches); it is **NOT TESTED** and must be run by the owner — exact commands in `evidence/dev_t1r_branch_coverage/sudo_commands.md`.

| Level | What | Command | sudo | Done 2026-11-03 |
|---|---|---|---|---|
| 1 | Re-derive DEV-T1r states from raw Falco events | `python3 report/tools/e4_reclassify.py` (DEV rows) | no | yes |
| 1 | Extract the exception-relevant event fields | `python3 evidence/dev_t1r_branch_coverage/extract_dev_fields.py` | no | yes |
| 1 | Prove `proc.exe`=argv0 / `proc.name`=`memfd:…` from the benign memfd probe (settles B1/B4) | see `evidence/P1_DEV_T1r/reproduction.md` step (c) | no | yes |
| 2 | Validate v1 + R4 syntax on the installed Falco | `falco -V /etc/falco/falco_rules.yaml -V rules/custom_rules.yaml -V rules/candidate_rules_v2.yaml` | no | yes (0 err/0 warn) |
| 3 | Load v1+R4, run DEV-T1r/T1/branch tests, measure, roll back | see `evidence/dev_t1r_branch_coverage/sudo_commands.md` | **yes** | **NO — NOT TESTED** |

## What level 3 will establish (and its IDs)

New test IDs, separate from E1–E5 (never overwrite those); full definitions in `evidence/P1_DEV_T1r/test_definitions.csv`:

- **DIAG-FIELDS** direct capture of `proc.exe`/`proc.name`/… on the live DEV-T1r memfd execve (least-disruptive, Method A) → turns B1/B4 from VERIFIED-by-semantics into VERIFIED-by-direct-capture.
- **R4-A** DEV-T1r with R4 loaded → expect R4 fires (true positive).
- **R4-B** T1 control with R4 loaded → expect R4 silent, default rule fires.
- **R4-D/E** ordinary exec / process named runc (non-memfd) → expect R4 silent.
- **NT-B1** memfd named `runc` → does `proc.name` become `runc` (branch B1)?
- **NT-B2** memfd exec whose live parent runs from a file named `runc` → does `proc.pname` = `runc` at the memfd execve (branch B2)?
- **NT-B4** argv0 = the exempt string, memfd name different → is `proc.exe` the argv0 or the memfd name (branch B4)?

Scenario **R4-C** (legitimate runc memfd clone, the key false-positive test) is **not reproducible on this VM**: runc 1.3.3 here does not clone via memfd (0 `memfd_create` from containers across the 500-container E2 churn). It stays NOT TESTED until a runc build/configuration that memfd-clones is available. Do not claim R4 is false-positive-safe without it.

## Prerequisites for level 3

- Disposable VM with a snapshot to roll back to; no `--privileged`, no host mounts.
- Falco 0.45.0, ruleset `falco-rules-5.2.0` (sha256 `30a1a602…`), modern eBPF; `falcoctl-artifact-follow` stopped so the ruleset hash stays frozen.
- `sudo ./preflight.sh default` PASS.
- The lab images built and `sudo ./labctl.sh up`.

After level 3, record results in a new `docs/dev_t1r_level3_results.md` with the per-test IDs, raw `falco_events.json` excerpts, SHA-256, and update `docs/r4_mitigation_evaluation.md` acceptance checkboxes from NOT TESTED to the actual outcome.
