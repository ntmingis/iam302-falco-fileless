# Pre-registration — P1-A: DIAG-FIELDS & branch isolation (NT-B1/B2/B4)

Status at registration: **NOT TESTED** (no sudo for the assistant; owner runs the privileged steps).
Registered before any run; hash in `rc4/prereg/PREREG_LEDGER.txt`.

## Hypothesis
At the DEV-T1r memfd execve, the four branches of `known_memfd_execution_processes` are decided by these fields:
`proc.exepath` (B3, verified match), `proc.name` (B1, inferred non-match), `proc.pname` (B2, inferred non-match),
`proc.exe` (B4, inferred non-match). Direct capture of all four at the live event should either confirm the
inferences or refute them.

## Variants and n
Owner runbook (frozen 2026-11-03): `evidence/dev_t1r_branch_coverage/sudo_commands.md` §B (DIAG-FIELDS) and §C
(NT-B1, NT-B2, NT-B4). n = 5 deterministic repetitions each. Ruleset: installed **default** + `lab_diag_fields.yaml`,
loaded into a bounded temporary `falco --modern-bpf -M` instance via `-r`, `rule_matching=all`. Method A only
(no change to `/etc/falco`, no service restart). Payloads are the benign memfd/echo variants already defined in that
runbook; the assistant does not introduce new payloads here.

## Outcome categories (per field, per variant)
- **CAPTURED** = field present and non-empty in the `LAB Diag memfd fields` event → may be cited as directly verified.
- **EMPTY** = present but empty string → stays inferred.
- **ABSENT** = field not in the event (or null/`<NA>`) → stays inferred / NOT TESTED.
- Branch "matched" (NT tests, default ruleset): the default `Fileless execution via memfd_create` is **suppressed**
  for that exec AND the DIAG event shows the deciding field holds the exempt value. If suppression cannot be
  attributed to exactly one field, the test is **INCONCLUSIVE**.

## Expected outcome (design intent, not a result)
DIAG: `proc.exepath=memfd:runc_cloned:/proc/self/exe`, `proc.name=memfd:runc_clon`, `proc.exe=x`,
`proc.pname=containerd-shim`, `proc.is_exe_from_memfd=true`. NT-B1 → default fires (B1 not bare `runc`).
NT-B4 → default suppressed, `proc.exe`=argv0 (B4 spoofable). NT-B2 → suppressed only if `proc.pname=runc` is observed.

## Decision rule
Upgrade B1 or B4 in `branch_matrix_rc4.csv` from INFERRED to VERIFIED **only** for a field that printed CAPTURED with
the exempt value at the DEV-T1r/NT event. Any ABSENT/EMPTY deciding field → the branch stays INFERRED and the test is
recorded INCONCLUSIVE. A refutation (e.g. default fires where suppression was expected) is recorded as-is.
