# P1 scorer audit (C6) — 2026-11-04

## The v1 bug (precise)
`score_p1.py` v1 (`score_branches`) collected the branch-deciding field values by iterating the `LAB Diag memfd fields`
events of **both** `diag_fields_raw.json` **and** `branch_isolation_raw.json`, taking the first `CAPTURED` value per
field across all of them:

```
for src, evs in (("diag_fields_raw.json", diag), ("branch_isolation_raw.json", iso)):
    for e in evs:
        if e.get("rule") != DIAG_RULE: continue
        o = e.get("output_fields", {})
        for k in FIELDS:
            if field_state(o,k)=="CAPTURED" and k not in captured: captured[k]=(o[k],src)
```

The DIAG rule (`spawned_process and container.name startswith "falco-lab-"`) matches **every** exec in the lab
container, not only the memfd execve. So `captured[...]` could be filled from the `docker exec python3` wrapper process
or from the NT-B2 `exec -a runc` process. Observed effect on the real run `rc4_p1_20261104T123454Z`
(`branch_matrix_rc4_scorerv1_DEFECTIVE.csv`): B3 `proc.exepath` was reported as `/usr/local/bin/python3`, B1/B4
`proc.name/proc.exe` as `python3`, B2 `proc.pname` as `runc` — all values of the **wrong process**, not the memfd
execve. The upgrade decision (B1/B4 → VERIFIED) would then rest on a field value that was never the memfd exec's.

## The v2 fix — identity selection, not value selection
v2 reads **only** `diag_fields_raw.json` and requires the event to be the memfd execve itself:

```
for src, evs in (("diag_fields_raw.json", diag),):
    for e in evs:
        if e.get("rule") != DIAG_RULE: continue
        o = e.get("output_fields", {})
        if str(o.get("proc.is_exe_from_memfd")).lower() != "true": continue   # identity gate
        ...
```

Selection keys = **(rule name == `LAB Diag memfd fields`) AND (`proc.is_exe_from_memfd` == true) AND (file ==
`diag_fields_raw.json`, the DEV-T1r DIAG run)**. The companion per-token scorer `score_p1_tokens.py` additionally keys
each event to its test by the **token substring** (unique per payload, e.g. `DIAG_…_r3`) and reports `default_memfd`
and `R4` alert counts by rule name. **Neither scorer ever selects an event by whether a field equals its expected
value** — events are chosen by rule identity, the memfd-exec flag, the source file and the per-run token; the field
values are then read out of whatever event those keys selected. (`evt.type` and `pid` are not used as keys: the DIAG
rule already fires once per exec and `is_exe_from_memfd` distinguishes the memfd execve from its parent; `pid` is not
emitted by the diagnostic rule's output, so it is not available as a key and is not relied on.)

## v1 vs v2 on the same raw files (`evidence/P1_DEV_T1r/raw_logs/rc4_p1_20261104T123454Z`)
| Branch | field | v1 captured (defective) | v2 captured (memfd execve) | v2 status |
|---|---|---|---|---|
| B1 | proc.name | `python3` | `memfd:runc_clon` | VERIFIED (captured) |
| B2 | proc.pname | `runc` | `containerd-shim` | INFERRED (captured, consistent) |
| B3 | proc.exepath | `/usr/local/bin/python3` | `memfd:runc_cloned:/proc/self/exe` | VERIFIED (consistent) |
| B4 | proc.exe | `python3` | `x` | VERIFIED (captured) |

Independent recount (`rc4/tools/recount_p1.py`, separate code path) reproduces the v2 values exactly.

## Quoted raw lines backing the VERIFIED upgrades (C5)
sha256 is of the full JSON line including its trailing newline.
- **B3 / DEV-T1r** memfd execve: `diag_fields_raw.json:3`
  sha256 `1214efacfb24b5c42202b1c30278f514d9f641f7eda1bdca584bd4630b5cb194`
  — `proc.exepath=memfd:runc_cloned:/proc/self/exe`, `proc.is_exe_from_memfd=true`.
- **B4 / NT-B4** (argv0-only bypass): `branch_isolation_raw.json:4`
  sha256 `3367b469b31b075c1497727d95e314520a2a853f3df39761316eceea47fbaac2`
  — `proc.exe=memfd:runc_cloned:/proc/self/exe`, `proc.exepath=memfd:not_runc_name` (so B3 cannot match; B4's field
  carries the exempt value), default memfd rule fired 0/5 for this token.
- **B1 / NT-B1** (non-match control): `branch_isolation_raw.json:7`
  sha256 `9a94eecfe83d9c3c28f7e77a019ec3bff1cb019e40e560cab39ec0f74beb768e`
  — `proc.name=memfd:runc` (prefixed, so a bare `runc` list match is impossible), default memfd rule fired 5/5.

## Unit test
`rc4/tools/test_p1_scorer_bug.py` builds a synthetic `diag_fields_raw.json` with a decoy parent DIAG event
(`is_exe_from_memfd=false`, `exepath=/usr/local/bin/python3`) placed **before** the real memfd event, then calls
`score_p1.v1_defective.py` and `score_p1.py` (v2). It asserts v1 reports B3=`/usr/local/bin/python3` (the bug) and v2
reports B3=`memfd:runc_cloned:/proc/self/exe` (the fix). Result: **PASS**.
