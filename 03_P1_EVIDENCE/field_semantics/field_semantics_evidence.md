# Field-semantics evidence for the four exception branches (P1, 2026-11-03)

This file settles, from **existing raw evidence** (no new privileged run), how Falco 0.45.0 on this VM populates the four fields the `known_memfd_execution_processes` exception compares, and therefore which branches can and cannot match DEV-T1r. It corrects an earlier over-grading of branch B4.

## The exception (4-way OR), as installed

`/etc/falco/falco_rules.yaml` (sha256 `30a1a60263ab97650c851011468da03b17fc0096a7cfa3b6686eba5de73b865b` = `falco-rules-5.2.0`):

```yaml
- list: known_memfd_execution_binaries
  items: [runc]
- macro: known_memfd_execution_processes
  condition: >
    (proc.name in (known_memfd_execution_binaries))        # B1: proc.name  == runc
    or (proc.pname in (known_memfd_execution_binaries))     # B2: proc.pname == runc
    or (proc.exepath = "memfd:runc_cloned:/proc/self/exe")  # B3
    or (proc.exe     = "memfd:runc_cloned:/proc/self/exe")  # B4
```

## Two payloads (verbatim from `run_e1.sh`)

| Variant | `memfd_create(name)` | `execve(fd, argv, …)` |
|---|---|---|
| T1 control (benign) | `falco_benign_memfd` | `argv = ['falco_memfd_py', <token>]` |
| DEV-T1r (spoof) | `runc_cloned:/proc/self/exe` | `argv = ['x', <token>]` |

So the **memfd name** and **argv[0]** are independently chosen by the payload. This is the whole point: the exception compares attacker-chosen strings.

## Primary evidence — a memfd exec that captured all four field types

The probe run `results/e1_probe_20261020_235831_probe/falco_events.json`, rule `LAB Probe exec fields` (an INFORMATIONAL diagnostic, `rules/.../lab_probe.yaml`), recorded a benign memfd exec with **`proc.exe` present** (the DEV and E4 runs never templated `%proc.exe`, which is why B4 was previously only inferred):

```
proc.is_exe_from_memfd = True
proc.name              = 'memfd:falco_ben'              # comm = "memfd:" + name, truncated to 15 chars
proc.exe               = 'falco_memfd_py'               # == argv[0]  (NOT the memfd name)
proc.exepath           = 'memfd:falco_benign_memfd'     # == "memfd:" + full memfd name
proc.args              = 'memfd_r1_1792515518'
evt.arg.flags          = 'EXE_WRITABLE|EXE_FROM_MEMFD'
```

This establishes three field rules on this exact VM/Falco build:

1. **`proc.exe` = argv[0].** Here argv[0]=`falco_memfd_py` and `proc.exe`=`falco_memfd_py`, while the memfd name differs (`falco_benign_memfd`). `proc.exe` is **not** the memfd path.
2. **`proc.name` = `memfd:` + (memfd name, truncated to 15 chars).** Here `memfd:falco_ben`. It is always prefixed with `memfd:`, so it can never equal the bare string `runc`.
3. **`proc.exepath` = `memfd:` + (full memfd name).** Here `memfd:falco_benign_memfd`; attacker-chosen in full.

## Applying the rules to DEV-T1r

DEV-T1r raw (`results/e1_custom_20261021_012554_dev/falco_events.json`, rule `LAB memfd exec masquerading as runc clone`, all 5 trials identical). Directly captured: `proc.exepath`, `proc.pname`, `proc.pexepath`, `proc.cmdline`. `proc.exe`/`proc.name` were **not** templated by that rule, so they are read via the field rules above (and via `cmdline`).

| Branch | Field | Recorded in DEV raw? | DEV-T1r value | How obtained | Matches exempt? | Grade |
|---|---|---|---|---|---|---|
| B1 | `proc.name` | **no** | (by semantics) `memfd:runc_clon` | probe rule #2 (`proc.name`=`memfd:`+name); DEV value not captured | no — prefixed `memfd:`, ≠ `runc` | INFERRED |
| B2 | `proc.pname` | yes | `containerd-shim` | directly captured in DEV raw | no — ≠ `runc` | VERIFIED |
| B3 | `proc.exepath` | yes | `memfd:runc_cloned:/proc/self/exe` | directly captured in DEV raw | **yes** — exact match | VERIFIED |
| B4 | `proc.exe` | **no** | (by semantics) `x` | probe rule #1 (`proc.exe`=argv0) + payload argv0=`x`; DEV value not captured | no — ≠ exempt string | VERIFIED FIELD SEMANTICS; DEV-SPECIFIC VALUE INFERRED |

Audited fact: the DEV-T1r alert (`LAB memfd exec masquerading as runc clone`) templated only `proc.cmdline`, `proc.exepath`, `proc.pexepath`, `proc.pname` — **`proc.name` and `proc.exe` are absent from its `output_fields`.** `proc.name` is therefore **not** read from the `proc.cmdline` first token (that is an inference, not the field). B1 and B4 non-matches rest on probe-proven field semantics plus the known payload, not on a captured DEV value.

## Conclusion

- **B3 is the only branch whose matching value was directly captured** in the DEV-T1r event (`proc.exepath`). It is the sole *directly verified* matching branch.
- **B2** non-match is also directly verified (captured `proc.pname=containerd-shim`).
- **B1** non-match is **INFERRED** (the `proc.name` field was not recorded for DEV-T1r; the probe shows the semantics but not the DEV value). **B4** non-match is **field-semantics-verified with an inferred DEV value** (`proc.exe` not recorded either). DEV-T1r could additionally match B1/B4 only if the probe-proven semantics were wrong for this event — not expected, not directly verified.
- The residual: the DEV-specific `proc.exe`/`proc.name` values were not captured. The one-shot diagnostic that templates `%proc.exe %proc.name` on the live DEV-T1r event (reusing `lab_probe.yaml`, least-disruptive, `evidence/dev_t1r_branch_coverage/sudo_commands.md` §3A) would turn B1/B4 into direct captures. It does not change the conclusion; it removes the last inferential step.
- **B4 is independently spoofable** by setting argv[0]=`memfd:runc_cloned:/proc/self/exe` regardless of the memfd name (test NT-B4). DEV-T1r does not exercise it, but it widens the exception's attack surface and is why mitigation R4 keys on the whole macro, not on one field.

Source raw files (unmodified E1–E5 evidence; read-only):
- `results/e1_probe_20261020_235831_probe/falco_events.json`
- `results/e1_custom_20261021_012554_dev/falco_events.json`
- `results/e1_default_20261021_005859_dev/falco_events.json` (0 bytes → default miss 5/5)
