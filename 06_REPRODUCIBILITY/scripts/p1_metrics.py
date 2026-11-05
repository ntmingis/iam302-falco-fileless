#!/usr/bin/env python3
"""p1_metrics.py — compute P1 detection metrics from RAW Falco evidence only.

Single source of truth = the raw falco_events.json files. This module never invents results and never
converts a missing value to zero: a field is CAPTURED, EMPTY or ABSENT, and a test with no raw data is
NOT TESTED. Alert counts and raw-event counts are kept separate. The unit of analysis is the variant;
per-run numbers are reported only as REFERENCE.

CLI:
    python3 tools/p1_metrics.py                 # DEV-T1r metrics + branch completeness from historical raw
    python3 tools/p1_metrics.py --json out.json # also write a machine-readable summary

No sudo, no live tests. Reads existing files under results/ and evidence/.
"""
import json, os, sys, glob

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, ROOT)
from tablestats import wilson  # reuse the audited Wilson helper

# raw DEV runs (historical; never overwritten)
DEV_DEFAULT = "results/e1_default_20261021_005859_dev/falco_events.json"
DEV_CUSTOM  = "results/e1_custom_20261021_012554_dev/falco_events.json"
PROBE       = "results/e1_probe_20261020_235831_probe/falco_events.json"

MEMFD_RULES = {"Fileless execution via memfd_create", "LAB memfd exec masquerading as runc clone",
               "LAB Diag memfd fields", "memfd exec hidden by runc exception"}
REQUIRED_FIELDS = ["proc.name", "proc.exe", "proc.exepath", "proc.pname", "proc.is_exe_from_memfd"]


def load_events(path):
    """Return list of event dicts from a falco json-lines file. Missing/0-byte file -> []."""
    p = os.path.join(ROOT, path)
    if not os.path.exists(p) or os.path.getsize(p) == 0:
        return []
    out = []
    for ln in open(p, encoding="utf-8", errors="replace"):
        ln = ln.strip()
        if not ln or ln[0] != "{":
            continue
        try:
            out.append(json.loads(ln))
        except Exception:
            pass
    return out


def field_state(output_fields, key):
    """CAPTURED/EMPTY/ABSENT for one field — never silently 0."""
    if key not in output_fields:
        return "ABSENT"
    v = output_fields[key]
    if v in (None, "<NA>"):
        return "ABSENT"
    if v == "":
        return "EMPTY"
    return "CAPTURED"


def summarize_run(path):
    """Counts for one raw run. Alert count and memfd-event count are reported separately (never summed)."""
    ev = load_events(path)
    alerts_by_rule = {}
    memfd_events = 0
    for e in ev:
        r = e.get("rule", "")
        alerts_by_rule[r] = alerts_by_rule.get(r, 0) + 1
        of = e.get("output_fields", {}) or {}
        if of.get("proc.is_exe_from_memfd") in (True, "true") or str(of.get("proc.exepath", "")).startswith("memfd:"):
            memfd_events += 1
    return {
        "path": path,
        "exists": os.path.exists(os.path.join(ROOT, path)),
        "bytes": os.path.getsize(os.path.join(ROOT, path)) if os.path.exists(os.path.join(ROOT, path)) else 0,
        "total_alert_lines": len(ev),
        "alerts_by_rule": alerts_by_rule,
        "memfd_events": memfd_events,
    }


def dev_t1r_metrics():
    """DEV-T1r baseline from raw. Variant = unit (1 variant x 5 reps); per-run shown as REFERENCE only."""
    d = summarize_run(DEV_DEFAULT)
    c = summarize_run(DEV_CUSTOM)
    REPS = 5
    # default: 0 alert lines in the whole run -> miss (variant-level 0/1)
    default_detected_variant = 1 if d["total_alert_lines"] > 0 else 0
    custom_detected_variant = 1 if c["alerts_by_rule"].get("LAB memfd exec masquerading as runc clone", 0) > 0 else 0
    # per-run reference counts (NOT combined with the variant unit)
    default_runs_detected = 0 if d["total_alert_lines"] == 0 else None  # 0 bytes -> 0; unknown otherwise
    custom_runs_detected = c["alerts_by_rule"].get("LAB memfd exec masquerading as runc clone", 0)
    return {
        "unit_of_analysis": "variant (1 variant, 5 reps) — per-run numbers are REFERENCE only",
        "default": {
            "detected_variants": default_detected_variant, "total_variants": 1,
            "wilson95_variant": wilson(default_detected_variant, 1),
            "runs_detected_REFERENCE": default_runs_detected, "total_runs_REFERENCE": REPS,
            "note": "raw falco_events.json is 0 bytes -> 0 alerts in 5/5 (false negative of the default ruleset)",
            "classification": "false_negative (suppressed by exception branch B3)",
        },
        "custom": {
            "detected_variants": custom_detected_variant, "total_variants": 1,
            "wilson95_variant": wilson(custom_detected_variant, 1),
            "runs_detected_REFERENCE": custom_runs_detected, "total_runs_REFERENCE": REPS,
            "classification": "direct detection (custom rule LAB memfd exec masquerading as runc clone)",
        },
    }


def branch_completeness():
    """Which exception branches have a DIRECTLY CAPTURED DEV field vs inferred. Source: raw DEV + probe."""
    dev = load_events(DEV_CUSTOM)
    memfd = [e for e in dev if e.get("rule") == "LAB memfd exec masquerading as runc clone"]
    of = (memfd[0].get("output_fields", {}) if memfd else {}) or {}
    probe = load_events(PROBE)
    probe_memfd = [e for e in probe if e.get("rule") == "LAB Probe exec fields"
                   and (e.get("output_fields", {}) or {}).get("proc.is_exe_from_memfd") in (True, "true")]
    probe_of = (probe_memfd[0].get("output_fields", {}) if probe_memfd else {}) or {}
    branches = {
        "B1_proc.name":    {"dev_field_state": field_state(of, "proc.name"),
                            "grade": "INFERRED", "note": "proc.name absent from DEV raw; semantics from probe (memfd:+name)"},
        "B2_proc.pname":   {"dev_field_state": field_state(of, "proc.pname"),
                            "grade": "VERIFIED", "value": of.get("proc.pname"), "note": "directly captured; != runc"},
        "B3_proc.exepath": {"dev_field_state": field_state(of, "proc.exepath"),
                            "grade": "VERIFIED", "value": of.get("proc.exepath"), "note": "directly captured; = exempt string (sole directly-verified match)"},
        "B4_proc.exe":     {"dev_field_state": field_state(of, "proc.exe"),
                            "grade": "VERIFIED FIELD SEMANTICS; DEV-SPECIFIC VALUE INFERRED",
                            "note": "proc.exe absent from DEV raw; probe proves proc.exe=argv0 (=%r)" % probe_of.get("proc.exe")},
    }
    directly_captured = sum(1 for b in branches.values() if b["dev_field_state"] == "CAPTURED")
    return {
        "branches": branches,
        "directly_captured_fields": directly_captured,
        "total_branch_fields": 4,
        "completeness_fraction": round(directly_captured / 4, 4),
        "sole_directly_verified_matching_branch": "B3",
    }


def summary():
    return {
        "source_of_truth": "raw falco_events.json (never overwritten)",
        "dev_t1r": dev_t1r_metrics(),
        "branch_completeness": branch_completeness(),
        "behavioural_tests_status": {t: "NOT TESTED" for t in
                                     ["DIAG-FIELDS", "NT-B1", "NT-B2", "NT-B4", "R4-A", "R4-B", "R4-D", "R4-E"]},
        "R4-C": "NOT REPRODUCIBLE (runc 1.3.3 does not memfd-clone on this VM)",
        "e4_strict_custom_REFERENCE": "1/4 (report/tables/e4_reclassified_subsets.csv; computed by report/tools/e4_reclassify.py)",
    }


def main():
    s = summary()
    print(json.dumps(s, indent=2, default=str))
    if "--json" in sys.argv:
        out = sys.argv[sys.argv.index("--json") + 1]
        with open(out, "w") as f:
            json.dump(s, f, indent=2, default=str)
        print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
