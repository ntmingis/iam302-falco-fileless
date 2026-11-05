# DEV-T1r baseline audit (P1.1, 2026-11-03)

Status of the baseline claims: **VERIFIED** against raw logs. Interpretation bounds stated at the end.

## What DEV-T1r is

A benign payload run inside `falco-lab-target` (a default Docker container):

```
python3 -c "import os,sys
fd=os.memfd_create('runc_cloned:/proc/self/exe'); os.write(fd,open('/bin/echo','rb').read()); os.execve(fd,['x',sys.argv[1]],{})" <token>
```

It creates an anonymous in-memory file, names it `runc_cloned:/proc/self/exe`, writes the bytes of `/bin/echo`, and executes it by fd. The kernel shows the executable path as `memfd:runc_cloned:/proc/self/exe`. The payload runs `/bin/echo` only; there is no exploit code. Source: `run_e1.sh` `run_dev_memfd_runcname`.

## Baseline claims vs. raw evidence

| Claim | Raw evidence | Status |
|---|---|---|
| Default ruleset: 0 alerts in 5/5 trials | `results/e1_default_20261021_005859_dev/falco_events.json` is **0 bytes** (no event of any rule during the run); `runs.csv` has 5 rows, all exit 0 | VERIFIED |
| Auditd observed `memfd_create` in 5/5 | per the run manifest and `analysis/…_dev/e1_detail.csv` (auditd_specific 5/5); raw `audit.log` present in the run dir | VERIFIED (from the parsed detail; raw audit excluded from the public package) |
| T1 control detected by default rules | E1 run: `Fileless execution via memfd_create@falco-lab-target` fires 5/5 for T1 (memfd named `falco_benign_memfd`) | VERIFIED (`e1_summary.csv`) |
| Custom v1 detected DEV-T1r 5/5 | `results/e1_custom_20261021_012554_dev/falco_events.json`: `LAB memfd exec masquerading as runc clone` [Critical] fires 5/5 | VERIFIED (`extract_dev_fields.py`) |
| Payload executes (not blocked) | exit 0 and token/marker in every `dev_memfd_runcname_*.out` | VERIFIED |

Recomputed independently of the parser by `evidence/dev_t1r_branch_coverage/extract_dev_fields.py` and `report/tools/e4_reclassify.py` (DEV rows). The 0-byte default event file is the strongest single fact: the Critical rule `Fileless execution via memfd_create` does not fire, and neither does anything else.

## Why the default rule is silent

`Fileless execution via memfd_create` has condition `spawned_process and proc.is_exe_from_memfd=true and not known_memfd_execution_processes` (`/etc/falco/falco_rules.yaml` L1266-1275). The macro `known_memfd_execution_processes` is true when any of four branches hold. At the memfd execve the captured fields are:

- `proc.exepath = memfd:runc_cloned:/proc/self/exe` → matches branch B3 → macro true → `not macro` false → **rule suppressed**.

See `docs/dev_t1r_branch_coverage.md` for all four branches.

## Interpretation bounds (what 0/5 does and does not mean)

- The five trials are **repeated observations of one variant**, not five independent mechanisms. They are deterministic (all 5/5 or all 0/5).
- 0/5 means: under this exact setup (Falco 0.45.0, ruleset `falco-rules-5.2.0` sha256 `30a1a602…`, modern eBPF, Docker 28.4.0 / runc 1.3.3, kernel 6.8, this payload), the default ruleset raised no alert. It is **not** proof that the event can never be detected: Auditd saw it, the custom rule caught it, and a different field choice would catch it.
- The inference is limited to the tested configuration. A different Falco version, ruleset, driver, or a payload with a different memfd name would change the result.
