#!/usr/bin/env python3
"""extract_dev_fields.py - P1: pull the memfd-related event fields from the DEV-T1r runs (raw, read-only).
Prints, per rule, the captured output_fields that bear on the four exception branches.
Usage: python3 evidence/dev_t1r_branch_coverage/extract_dev_fields.py
Note: output_fields only contains fields named in each rule's `output:` string; absent fields show as None.
"""
import json, os
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RUNS = {"default": "e1_default_20261021_005859_dev", "custom": "e1_custom_20261021_012554_dev"}
FIELDS = ("proc.name", "proc.pname", "proc.exepath", "proc.pexepath", "proc.cmdline", "container.name")
for tag, run in RUNS.items():
    p = os.path.join(ROOT, "results", run, "falco_events.json")
    sz = os.path.getsize(p)
    print(f"\n=== {tag} run {run}  (falco_events.json = {sz} bytes) ===")
    if sz == 0:
        print("  0 alerts in the whole run -> DEV-T1r miss 5/5 (default ruleset)."); continue
    seen = {}
    for line in open(p):
        if not line.strip(): continue
        j = json.loads(line); o = j.get("output_fields", {}); rule = j["rule"]
        seen.setdefault(rule, (j.get("priority"), {k: o.get(k) for k in FIELDS}))
    for rule, (prio, fv) in seen.items():
        print(f"  RULE [{prio}] {rule}")
        for k, v in fv.items():
            v = (str(v).split(chr(10))[0] + " …") if v and chr(10) in str(v) else v
            print(f"     {k} = {v}")
