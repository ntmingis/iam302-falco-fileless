# DEV-T1r exception branch coverage (P1.2, 2026-11-03; revised)

The exception `known_memfd_execution_processes` is a **4-way OR**. This document verifies, per branch, its exact condition, the actual event-field value, the expected and observed evaluation, the evidence file, and a verification status — **without accepting the earlier "B3 is the sole suppressor" claim blindly**. A 2026-11-03 semantic audit against the exact DEV-T1r raw record corrected two over-grades: **B1 is downgraded VERIFIED → INFERRED** (the earlier grade read `proc.name` from the `proc.cmdline` first token, which is an inference, not the field — and the DEV event never recorded `proc.name`), and **B4 is labelled "VERIFIED FIELD SEMANTICS; DEV-SPECIFIC VALUE INFERRED"** (the probe proves `proc.exe`=argv0, but the DEV `proc.exe` field was not recorded). The refined conclusion: **B3 is the only branch whose matching value was directly captured in the DEV-T1r event** (B2's non-match is also directly captured; B1/B4 non-matches rest on field semantics + payload, not a captured DEV value).

Machine-readable: `evidence/dev_t1r_branch_coverage/branch_matrix.csv`. Field-semantics proof: `evidence/P1_DEV_T1r/field_semantics_evidence.md`. The four fields are **not interchangeable** — each has a distinct source in Falco 0.45.0.

## Status vocabulary
- **VERIFIED** — the branch's own field value is established from a **directly captured event field** in the DEV-T1r raw record (this VM, this Falco build).
- **VERIFIED FIELD SEMANTICS; DEV-SPECIFIC VALUE INFERRED** — how the field is populated was directly captured on an analogous on-VM memfd exec (the probe run), but the field was **not** present in the DEV-T1r raw record, so the DEV-specific value is inferred from that semantics plus the known payload.
- **INFERRED** — the exact raw field was not recorded for DEV-T1r; the conclusion rests on field semantics and/or payload, not on a captured DEV value.
- **INCONCLUSIVE** — cannot be isolated without changing another field; reason recorded.
- **NOT TESTED** — needs a new privileged run.

## Which fields the DEV-T1r raw event actually recorded (audited 2026-11-03)
The alerting rule `LAB memfd exec masquerading as runc clone` templated only these `output_fields` (verified in `results/e1_custom_20261021_012554_dev/falco_events.json`, all 5 trials identical): `proc.cmdline`, `proc.exepath`, `proc.pexepath`, `proc.pname` (+ container/k8s/evt.time). **`proc.name` and `proc.exe` were NOT recorded.** Therefore only the branches keyed on `proc.exepath` (B3) and `proc.pname` (B2) can be graded from a directly captured DEV field; B1 (`proc.name`) and B4 (`proc.exe`) cannot, and are graded accordingly below. `proc.name` is **not** taken from the first token of `proc.cmdline` — that would be an indirect inference, not the field.

Official Falco 0.45.0 field semantics used here: `proc.name` = `task->comm` (kernel-limited to 16 chars); `proc.exe` = `argv[0]`; `proc.exepath` = executable path; `proc.pname` = parent's `proc.name`.

## Field semantics, proven on this VM (not assumed)

From the benign memfd probe `results/e1_probe_20261020_235831_probe/falco_events.json` (rule `LAB Probe exec fields`), which captured a memfd exec with **`proc.exe` present**:

| Field | Observed on the probe (memfd name `falco_benign_memfd`, argv0 `falco_memfd_py`) | Rule derived |
|---|---|---|
| `proc.exe` | `falco_memfd_py` | **= argv[0]**, not the memfd name |
| `proc.name` | `memfd:falco_ben` | **= `memfd:` + memfd name, truncated to 15 chars** → always prefixed, can never be bare `runc` |
| `proc.exepath` | `memfd:falco_benign_memfd` | **= `memfd:` + full memfd name** (attacker-chosen) |
| `proc.pname` | parent comm | kernel comm of the parent (reparented after `runc exec` exits) |

These three field rules are what let B1/B4 be graded from evidence rather than guessed.

## Branch coverage matrix (DEV-T1r)

DEV-T1r payload: `memfd_create('runc_cloned:/proc/self/exe')`, `execve(fd, ['x', <token>])`. DEV raw: `results/e1_custom_20261021_012554_dev/falco_events.json` (5/5 identical).

| Branch | Exact condition | Actual DEV-T1r field value | Expected evaluation | Observed result | Evidence file | Verification status |
|---|---|---|---|---|---|---|
| **B1** | `proc.name in (runc)` | `proc.name` **not recorded** in the DEV raw; by field semantics would be `memfd:runc_clon` (comm = `memfd:`+name, 16-char limit) | no match (prefixed `memfd:`, ≠ `runc`) | **does not suppress** (inferred) | probe run `proc.name=memfd:falco_ben` (semantics); **not** in DEV `output_fields` | **INFERRED** — exact raw `proc.name` field unavailable for DEV-T1r |
| **B2** | `proc.pname in (runc)` | `proc.pname = containerd-shim` (directly captured) | no match (≠ `runc`; runc already exited/reparented) | **does not suppress** | `dev_t1r_event_fields.txt` (DEV `output_fields`) | **VERIFIED** (direct capture) |
| **B3** | `proc.exepath = "memfd:runc_cloned:/proc/self/exe"` | `proc.exepath = memfd:runc_cloned:/proc/self/exe` (directly captured) | **match** | **suppresses** | `dev_t1r_event_fields.txt` (DEV `output_fields`) | **VERIFIED** (direct capture) |
| **B4** | `proc.exe = "memfd:runc_cloned:/proc/self/exe"` | `proc.exe` **not recorded** in the DEV raw; by field semantics = `argv[0]` = `x` | no match (≠ exempt string) | **does not suppress** (inferred value) | probe run `proc.exe=falco_memfd_py`=argv0 (semantics) + payload argv0=`x`; **not** in DEV `output_fields` | **VERIFIED FIELD SEMANTICS; DEV-SPECIFIC VALUE INFERRED** |

### What changed vs the previous version (2026-11-03 semantic audit)
- **B1: corrected VERIFIED → INFERRED.** The previous grade derived `proc.name` from the first token of `proc.cmdline`. That is an indirect inference, not the raw field; the DEV-T1r event never recorded `proc.name`. The probe run shows the on-VM semantics (`proc.name` = `memfd:`+name, so it can never be bare `runc`), which supports the non-match, but because the exact DEV `proc.name` value was not captured, the status is **INFERRED**. DIAG-FIELDS would capture it directly.
- **B4: VERIFIED FIELD SEMANTICS; DEV-SPECIFIC VALUE INFERRED.** The probe run directly captured `proc.exe`=argv[0] (`falco_memfd_py`, distinct from the memfd name) for a memfd exec on this VM, which settles the real question (`proc.exe` is argv0, not the memfd name). Applied to DEV-T1r's payload argv0=`x`, B4 does not match. But the DEV-T1r `proc.exe` field itself was **not** recorded, so this is field-semantics evidence plus an inferred DEV value — **not** a direct DEV-event capture.

## Conclusion
All four branch conditions have been evaluated against the exact installed upstream macro and supported Falco 0.45.0 field values. **Branch B3 (`proc.exepath`) is the sole branch whose matching value was directly captured in the DEV-T1r event**, so it is the only *directly verified* matching branch. **B2** non-match is also directly verified (captured `proc.pname=containerd-shim`). **B1** (non-match) is **INFERRED** and **B4** (non-match) is **field-semantics-verified with an inferred DEV value** — for both, the raw field was absent from the DEV record. DEV-T1r could additionally match B1 or B4 only if the on-VM field semantics proven by the probe were wrong for this specific event, which is not expected but is **not directly verified**. The single remaining direct-capture step (DEV-specific `proc.name`/`proc.exe`) is closed by test **DIAG-FIELDS** (least-disruptive, `sudo_commands.md §3A`); until then B3 remains the only branch confirmed by a captured DEV value.

Lineage note: at the *python3 start* event `proc.pname = runc` (docker-exec is launched by runc), but at the *memfd execve* (the only event the memfd rule evaluates) `proc.pname = containerd-shim`, because the transient `runc exec` process has exited and the process is reparented to the shim. So branch B2 — which **did** catch the real-runc FP in issue #3444 (`parent=runc`) — does not apply to this reparented spoof.

## Independently spoofable branches (relevant to R4)
- **B3** — verified spoofable (DEV-T1r).
- **B4** — spoofable in principle by setting argv[0] = the exempt string regardless of the memfd name (test **NT-B4**); not exercised by DEV-T1r but it widens the exception surface. This is why R4 keys on the whole `known_memfd_execution_processes` macro, not on `proc.exepath` alone.
- **B1/B2** — not reachable by renaming alone in DEV-T1r (B1 is always `memfd:`-prefixed; B2's runc parent has exited). Whether a live runc-named parent (NT-B2) can reach B2 is **NOT TESTED** (one earlier `prctl(PR_SET_NAME,"runc")` probe did not bypass).

## Untested isolation tests (NOT TESTED)
All benign (`/bin/echo`), in `falco-lab-target`, disposable VM. Definitions: `evidence/P1_DEV_T1r/test_definitions.csv`. Commands: `evidence/dev_t1r_branch_coverage/sudo_commands.md`.

| Test | Isolates | Method | Expected (default ruleset) |
|---|---|---|---|
| DIAG-FIELDS | all four fields | templated `%proc.exe %proc.name …` on live DEV-T1r (reuse `lab_probe.yaml`) | confirms the matrix above directly |
| NT-B1 | `proc.name` | memfd name = `runc` | `proc.name=memfd:runc` → B1 still no → default rule fires |
| NT-B2 | `proc.pname` | live parent exec'd from a file named `runc` | if `proc.pname=runc` → suppressed; else fires |
| NT-B4 | `proc.exe` | argv0 = exempt string, memfd name different | if suppressed → confirms `proc.exe`=argv0 and B4 spoofable |

## Evidence files
- `evidence/P1_DEV_T1r/field_semantics_evidence.md` — the proc.exe=argv0 / proc.name=memfd:… proof (primary new evidence)
- `evidence/dev_t1r_branch_coverage/dev_t1r_event_fields.txt` — captured DEV fields
- `evidence/dev_t1r_branch_coverage/branch_matrix.csv` — machine-readable matrix
- `evidence/dev_t1r_branch_coverage/upstream_memfd_rule_falco-rules-5.2.0_L1250-1290.yaml` — the installed rule+exception
- `evidence/dev_t1r_branch_coverage/falco_0.45.0_list_syscall.txt` — field reference
- `evidence/dev_t1r_branch_coverage/falco_validate_v1_and_v2_20261103.json` — `falco -V` (0 err/0 warn)
- `evidence/P1_DEV_T1r/environment_metadata.txt` — versions/hashes
