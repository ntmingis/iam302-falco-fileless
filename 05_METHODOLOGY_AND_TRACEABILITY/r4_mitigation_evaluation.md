# R4 mitigation evaluation (P1.4, 2026-11-03)

R4 is a candidate rule in `rules/candidate_rules_v2.yaml`. Overall status: **syntax VERIFIED, behaviour NOT TESTED.** R4 has not been loaded into the running sensor (that needs sudo; the owner runs it). Do not read any "expected" column below as a result.

## 1. Exact R4 definition (verbatim)

```yaml
- rule: LAB2 memfd exec covered by runc exception without real runc parent
  desc: exec tu memfd khop ngoai le runc cua rule default nhung tien trinh cha khong chay tu binary runc that (T1620)
  condition: >
    spawned_process and evt.res = SUCCESS and proc.is_exe_from_memfd = true
    and known_memfd_execution_processes
    and not proc.pexepath in (lab_runc_paths)
  output: >
    memfd exec hidden by runc exception (exepath=%proc.exepath argv0=%proc.exe name=%proc.name parent=%proc.pname
    parent_exepath=%proc.pexepath cmd=%proc.cmdline container=%container.name)
  priority: CRITICAL
  tags: [lab_candidate_v2, not_tested, fileless, T1620]
```

Dependencies: `spawned_process`, `known_memfd_execution_processes` (from the default `falco_rules.yaml`), and `lab_runc_paths` (from `rules/custom_rules.yaml`):

```yaml
- list: lab_runc_paths
  items: [/usr/bin/runc, /usr/sbin/runc, /usr/local/bin/runc, /usr/local/sbin/runc]
```

## 2. How R4 differs from custom v1

- v1 (`LAB memfd exec masquerading as runc clone`) keys on `proc.exepath startswith "memfd:runc_cloned" or proc.exe startswith "memfd:runc_cloned"` — i.e. it re-detects the **name** the attacker used. It covers B3/B4 only.
- R4 keys on `known_memfd_execution_processes` (the whole exception, all four branches) **and** `not proc.pexepath in (lab_runc_paths)`. So R4 fires for **any** memfd exec that the default exception would exempt, unless the parent genuinely runs from a runc binary. It covers the exception as a set, not a specific name.
- Trade-off: R4 depends on `proc.pexepath` (parent executable path, kernel-backed) being populated and being a reliable runc indicator.

**Why cover the whole macro, not just B3:** the branch analysis (`docs/dev_t1r_branch_coverage.md`, `evidence/P1_DEV_T1r/field_semantics_evidence.md`) shows the exception is spoofable on at least two independent branches — B3 (`proc.exepath` = attacker-chosen memfd name, used by DEV-T1r) and B4 (`proc.exe` = attacker-chosen argv[0], test NT-B4). A mitigation keyed only on the `memfd:runc_cloned…` string (custom v1) would miss a B4 argv0-spoof with a different memfd name. R4 keys on `known_memfd_execution_processes` as a whole and re-qualifies it with a kernel-backed parent check, so it covers any branch the attacker uses.

## 3. Scope and dependencies (static, VERIFIED)

- **Syntax/fields:** `falco -V /etc/falco/falco_rules.yaml -V rules/custom_rules.yaml -V rules/candidate_rules_v2.yaml` → 0 errors, 0 warnings, `schema_valid: true` (`evidence/dev_t1r_branch_coverage/falco_validate_v1_and_v2_20261103.json`, 2026-11-03). All fields exist in Falco 0.45.0.
- **No unavailable field:** `proc.pexepath`, `proc.is_exe_from_memfd`, `proc.exepath`, `proc.exe`, `proc.name`, `proc.pname` all present (`falco_0.45.0_list_syscall.txt`).
- **runc path on this VM:** `/usr/bin/runc` (`readlink -f $(which runc)`), which **is** in `lab_runc_paths`. So if real runc cloned via memfd, its child's `proc.pexepath` would be `/usr/bin/runc` and R4 would correctly not fire.
- **Does not modify upstream rules:** R4 is additive and lives in a separate file; it does not weaken or disable any default rule.

## 4. Scenario matrix (all behaviour NOT TESTED)

Scenarios A–F are the ones specified for this evaluation (A DEV-T1r, B T1 original memfd control, C legitimate runc clone / #3444, D ordinary executable process, E process with a similar executable name, F missing/incomplete parent-process information); G is an additional false-positive case kept for completeness. Benign test definitions and per-scenario expectations: `evidence/P1_DEV_T1r/test_definitions.csv`, `evidence/P1_DEV_T1r/expected_results.md`. Exact commands: `evidence/dev_t1r_branch_coverage/sudo_commands.md`. Expected = design intent, to be checked by a privileged run. Evidence hash column filled only after execution.

| # | Scenario | Payload (benign) | Expected R4 | Classification if met | Testable on this VM? |
|---|---|---|---|---|---|
| A | DEV-T1r (memfd named `runc_cloned:…`, parent not runc) | existing `run_dev_memfd_runcname` | **fires** (parent = containerd-shim ∉ lab_runc_paths) | true positive | Yes |
| B | T1 control (memfd named `falco_benign_memfd`) | existing `run_memfd` | default rule already fires; R4 **also** fires (exception not matched → `known_memfd_execution_processes` false → R4 condition false → **R4 does NOT fire**) | R4 correctly silent (default covers it) | Yes |
| C | Legitimate runc memfd clone (#3444) | real runc ≥1.1.15 clone | **does not fire** (parent `proc.pexepath` = runc path ∈ list) | true negative | **No** — runc 1.3.3 on this VM does not clone via memfd (0 `memfd_create` from containers in 500-container E2 churn); needs a runc build/config that clones |
| D | Ordinary process execution | any non-memfd exec | does not fire (`is_exe_from_memfd` false) | true negative | Yes |
| E | Unrelated process named like runc | process named `runc` doing a normal (non-memfd) exec | does not fire (`is_exe_from_memfd` false) | true negative | Yes |
| F | Parent executable unavailable/incomplete | memfd exec where `proc.pexepath` is empty/unreadable | **fires** (empty ∉ lab_runc_paths) — may be FP or TP depending on cause | needs judgement; document | Partially (hard to force) |
| G | Unexpected process lineage | memfd exec whose parent is a real runc at a non-listed path | **fires** (path ∉ list) → **false positive** | FP — fix by extending `lab_runc_paths` | Only if runc installed at a non-listed path |

## 5. Acceptance criteria and known trade-offs

R4 is acceptable only if (to be confirmed by the privileged run):

- [ ] Detects benign DEV-T1r (A) — **NOT TESTED**
- [ ] Does not FP on legitimate runc memfd clone (C) — **NOT TESTED** and **not reproducible on this VM** (runc here does not memfd-clone). This is the central open risk.
- [ ] Documented scope — done (this file)
- [x] No dependency on an unavailable field — VERIFIED
- [x] Validates with the installed Falco — VERIFIED (`falco -V`, 0 err/0 warn)
- [x] Does not silently break existing rules — VERIFIED (additive, separate file)

**Known trade-offs / limitations:**
1. R4 trusts `proc.pexepath` as the runc signal. If a real runc memfd-clones but its binary sits at a path not in `lab_runc_paths` (scenario G), R4 false-positives. Mitigation: populate `lab_runc_paths` per environment, or match `proc.aexepath` up the chain.
2. At the memfd execve the parent may already be reparented (DEV-T1r shows parent = containerd-shim, not the original runc). For the *real* runc clone, issue #3444 shows `parent=runc`, so `proc.pexepath` should be runc there — but this asymmetry is exactly why R4 can tell the two apart, and it rests on the unverified assumption that a real clone keeps a runc parent at the memfd execve. **NOT TESTED.**
3. R4 was designed from the same DEV-T1r variant it aims to catch. Measuring it on DEV-T1r is not an independent test; an independent memfd-spoof variant (E8) is needed before claiming generality.
4. Because scenario C cannot be reproduced on this VM, the most important FP question cannot be answered here. Until it is, R4 must be labelled a candidate, not a validated mitigation.
