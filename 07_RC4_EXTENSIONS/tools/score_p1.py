#!/usr/bin/env python3
"""score_p1.py - score P1-A (branch isolation) and P1-B (R4 scenarios) from the owner's raw Falco JSON.

Usage:  python3 -I rc4/tools/score_p1.py <raw_dir>
  <raw_dir> holds the JSON produced by evidence/dev_t1r_branch_coverage/sudo_commands.md sections B/C/D, i.e.
  diag_fields_raw.json, branch_isolation_raw.json, r4_scenarios_raw.json (any subset that exists).

FAIL-CLOSED: this script never invents a result. If a file is absent, its tests stay NOT TESTED. A branch is upgraded
to VERIFIED only when the deciding field printed CAPTURED (present, non-empty) in a real event. It does not modify any
raw file; it writes only rc4/tables/branch_matrix_rc4.csv and rc4/tables/r4_scenarios_rc4.csv.
"""
import csv, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
TBL = os.path.join(ROOT, "rc4", "tables")
DIAG_RULE = "LAB Diag memfd fields"
DEFAULT_MEMFD = "Fileless execution via memfd_create"
R4_RULE = "LAB2 memfd exec covered by runc exception without real runc parent"
FIELDS = ["proc.name", "proc.exe", "proc.exepath", "proc.pname", "proc.is_exe_from_memfd"]


def load(path):
    if not os.path.exists(path):
        return None
    evs = []
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            evs.append(json.loads(line))
        except ValueError:
            continue
    return evs


def field_state(o, k):
    if k not in o:
        return "ABSENT", ""
    v = o[k]
    if v in (None, "<NA>"):
        return "ABSENT", ""
    if v == "":
        return "EMPTY", ""
    return "CAPTURED", str(v)


def score_branches(raw_dir):
    """Return rows for branch_matrix_rc4.csv, keeping the RC3 inference columns and adding rc4_* columns."""
    base = [
        # branch, field, rc3_status, rc3_note
        ("B1", "proc.name", "INFERRED", "memfd name is prefixed 'memfd:' so proc.name cannot be bare 'runc'"),
        ("B2", "proc.pname", "INFERRED", "non-match captured once (pname=containerd-shim); runc-parent case untested"),
        ("B3", "proc.exepath", "VERIFIED", "DEV-T1r captured proc.exepath=memfd:runc_cloned:/proc/self/exe (RC3)"),
        ("B4", "proc.exe", "INFERRED", "argv0 spoofability inferred from field semantics"),
    ]
    diag = load(os.path.join(raw_dir, "diag_fields_raw.json"))
    iso = load(os.path.join(raw_dir, "branch_isolation_raw.json"))
    captured = {}   # field -> (value, source_file) for any CAPTURED diag field
    run_id = os.path.basename(raw_dir.rstrip("/"))
    # v2 fix (post-run, documented in deviations.md D-P1-2): take fields ONLY from the DIAG event of the DEV-T1r
    # memfd execve itself (proc.is_exe_from_memfd true, diag_fields_raw.json). v1 also read the docker-exec python3
    # parent events and the NT variants, reporting values of the wrong process.
    for src, evs in (("diag_fields_raw.json", diag),):
        if not evs:
            continue
        for e in evs:
            if e.get("rule") != DIAG_RULE:
                continue
            o = e.get("output_fields", {}) or {}
            if str(o.get("proc.is_exe_from_memfd")).lower() != "true":
                continue
            for k in FIELDS:
                st, val = field_state(o, k)
                if st == "CAPTURED" and k not in captured:
                    captured[k] = (val, src)
    rows = []
    any_data = bool(diag or iso)
    for branch, field, rc3_status, rc3_note in base:
        if not any_data:
            rc4_val, rc4_status = "", "NOT TESTED (no raw JSON present)"
        elif field in captured:
            rc4_val = captured[field][0]
            # upgrade only B1/B4 from INFERRED; B3 stays VERIFIED; record the captured value regardless
            rc4_status = "VERIFIED (captured)" if branch in ("B1", "B4") else rc3_status + " (captured, consistent)"
        else:
            rc4_val, rc4_status = "", "INCONCLUSIVE (deciding field ABSENT/EMPTY in captured events)"
        rows.append([branch, field, rc3_status, rc3_note, rc4_val, rc4_status, run_id if any_data else ""])
    return rows, any_data


def score_r4(raw_dir):
    evs = load(os.path.join(raw_dir, "r4_scenarios_raw.json"))
    run_id = os.path.basename(raw_dir.rstrip("/"))
    scen = [
        ("A", "DEV-T1r", "R4 fires, default silent -> TP"),
        ("B", "T1 control", "default fires, R4 silent -> R4 correctly silent"),
        ("D", "ordinary exec", "both silent -> TN"),
        ("E", "runc-like name non-memfd", "both silent -> TN"),
    ]
    rows = []
    if not evs:
        for s, desc, exp in scen:
            rows.append([s, desc, exp, "", "", "NOT TESTED (no r4_scenarios_raw.json)"])
        return rows, False
    r4_fired = sum(1 for e in evs if e.get("rule") == R4_RULE)
    default_fired = sum(1 for e in evs if e.get("rule") == DEFAULT_MEMFD)
    # We cannot attribute counts to scenarios without per-token tagging in this generic scorer:
    # report the observed totals and require the owner to confirm per-scenario tokens before classifying TP/TN.
    for s, desc, exp in scen:
        rows.append([s, desc, exp, "", "",
                     "PRESENT (raw JSON found; classify per token using the stdout logs) "
                     f"[totals in window: R4={r4_fired}, default_memfd={default_fired}]"])
    return rows, True


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    raw_dir = sys.argv[1]
    if not os.path.isdir(raw_dir):
        print(f"not a directory: {raw_dir}")
        sys.exit(2)
    os.makedirs(TBL, exist_ok=True)
    brows, bdata = score_branches(raw_dir)
    with open(os.path.join(TBL, "branch_matrix_rc4.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["branch", "deciding_field", "rc3_status", "rc3_note", "rc4_captured_value", "rc4_status", "rc4_run_id"])
        w.writerows(brows)
    rrows, rdata = score_r4(raw_dir)
    with open(os.path.join(TBL, "r4_scenarios_rc4.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scenario", "description", "expected_design_intent", "r4", "default_memfd", "rc4_status"])
        w.writerows(rrows)
    print(f"branch data present: {bdata}; r4 data present: {rdata}")
    print(f"wrote {TBL}/branch_matrix_rc4.csv and {TBL}/r4_scenarios_rc4.csv")
    if not (bdata or rdata):
        print("NO RAW JSON FOUND -> all P1 tests remain NOT TESTED (nothing was fabricated).")


if __name__ == "__main__":
    main()
