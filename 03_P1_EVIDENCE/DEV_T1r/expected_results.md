# Expected results (design intent — NOT measured) — P1 DEV-T1r & R4

Everything here is **design intent**, to be confirmed by the owner's privileged run (`evidence/dev_t1r_branch_coverage/sudo_commands.md`). Nothing below is a measured result. Validity of R4's syntax does **not** imply any of these behaviours.

## Branch diagnostics / isolation (default ruleset)

| Test | Expected observation | What it would establish |
|---|---|---|
| DIAG-FIELDS | `proc.exe=x`, `proc.name=memfd:runc_clon`, `proc.exepath=memfd:runc_cloned:/proc/self/exe`, `proc.pname=containerd-shim` | Direct capture confirming B3 matches, B1/B4 do not (removes the last inferential step) |
| NT-B1 | memfd named `runc` → `proc.name=memfd:runc` (still prefixed); default rule **fires** | B1 cannot be forced to bare `runc` via the memfd name → B1 unmatchable this way |
| NT-B2 | parent exec'd from file named `runc`; if `proc.pname=runc` at the memfd execve → **suppressed** | Whether B2 is reachable with a live runc-named parent (earlier `prctl(PR_SET_NAME)` rename did **not** work) |
| NT-B4 | argv0 = exempt string, memfd name different → if **suppressed**, confirms `proc.exe`=argv0 and B4 is independently spoofable | B4 reachability via argv0 spoofing |

Interpretation: with the **default** ruleset, *suppressed* (no `Fileless execution via memfd_create`) means that branch matched; *alert present* means it did not. Record the actual `proc.name/exe/exepath/pname` values, not just the alert. If a field cannot be set to exactly `runc`/the string without also changing another field, mark **INCONCLUSIVE**.

## R4 scenarios (default + v1 + R4 loaded)

| Scenario | Expected R4 | Expected default memfd rule | Classification if met |
|---|---|---|---|
| A. DEV-T1r | **fires** | silent (exempt by B3) | true positive |
| B. T1 control (ordinary memfd name) | silent | **fires** | R4 correctly silent (default covers it) |
| C. Legit runc memfd clone (#3444) | silent | silent (exempt) | true negative — **NOT reproducible on this VM** |
| D. Ordinary process (no memfd) | silent | silent | true negative |
| E. runc-like name, non-memfd | silent | silent | true negative |
| F. Missing/incomplete parent info | **fires** (empty ∉ list) | silent | judgement: TP or FP by cause |
| G. Real runc at unlisted path | **fires** | silent | **false positive** — fix via `lab_runc_paths` |

Acceptance gate (all currently open): R4 is a validated mitigation only once A fires, C does **not** false-positive, and F/G behaviour is understood. C is the central open risk and is not answerable on this VM.
