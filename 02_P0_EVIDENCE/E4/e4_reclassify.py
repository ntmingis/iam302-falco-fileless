#!/usr/bin/env python3
"""e4_reclassify.py - P0.1 (2026-11-03): recompute E4/DEV states from RAW logs and the reclassified subsets.

Independent of parse_e1.py: reads results/<run>/{runs.csv,falco_events.json,*.out} directly, applies its own
expected-rule map, and writes
  report/tables/e4_reclassified_variants.csv   per-variant raw recount (default + custom)
  report/tables/e4_reclassified_subsets.csv    subsets, k/n, Wilson 95% (variant unit) + run-unit reference
  report/tables/e4_sensitivity.csv             strict set with/without E4-T5c, E4-T2b
It then cross-checks against the historical report/tables/e4_unseen_summary.csv (read-only) and exits 1 on mismatch.
No sudo, no writes to results/ or analysis/.   Usage: python3 report/tools/e4_reclassify.py
"""
import csv, datetime, json, math, os, sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RUNS = {"default": "e1_default_20261021_002936_e4", "custom": "e1_custom_20261021_011709_e4",
        "default_dev": "e1_default_20261021_005859_dev", "custom_dev": "e1_custom_20261021_012554_dev"}
# variant -> (id, group, expected container prefix, rule-name substrings that count as direct)
VAR = {
    "e4_memfd_execveat": ("E4-T1b", "A", "falco-lab-target", ["Fileless execution via memfd_create"]),
    "e4_procfd_argv0":   ("E4-T3d", "A", "falco-lab-target", ["LAB Exec via proc fd"]),
    "e4_shm_argv0":      ("E4-T2b", "A", "falco-lab-shmexec", ["/dev/shm"]),
    "e4_python_stdin":   ("E4-T4b", "A", "falco-lab-target", ["LAB Interpreter inline"]),
    "e4_curl_script":    ("E4-T5b", "A", "falco-lab-client", ["LAB Download piped", "LAB Shell reading"]),
    "e4_curl_sh":        ("E4-T5c", "A", "falco-lab-client", ["LAB Download piped", "LAB Shell reading"]),
    "e4_preload_env":    ("E4-T6b", "B", "falco-lab-target", ["LAB Process started with LD_PRELOAD"]),
    "dev_memfd_runcname": ("DEV-T1r", "A", "falco-lab-target",
                           ["Fileless execution via memfd_create", "LAB memfd exec masquerading"]),
}
# P0.1 classification (docs/e4_independence_reclassification.md). Order = report order.
CLASS = {
    "DEV-T1r": ("known_in_sample", "used to write 'LAB memfd exec masquerading as runc clone' (DEV set)"),
    "E4-T1b": ("related_unseen", "execveat (syscall 322) like T1; same memfd mechanism"),
    "E4-T6b": ("related_unseen", "Group B; same LD_PRELOAD variable as T6"),
    "E4-T5c": ("related_unseen", "'| sh' literally enumerated in draft0 (2026-10-19) and v1; lineage rule added after variant was written"),
    "E4-T3d": ("strict_unseen", ""), "E4-T2b": ("strict_unseen", "conceived before v1 freeze (not executed); miss in both"),
    "E4-T4b": ("strict_unseen", ""), "E4-T5b": ("strict_unseen", ""),
}

def ms(t):
    b, _, f = t.rstrip("Z").partition(".")
    return int(datetime.datetime.fromisoformat(b).replace(tzinfo=datetime.timezone.utc).timestamp() * 1000) + int((f + "000")[:3])

def wilson(k, n, z=1.96):
    if n == 0: return float("nan"), float("nan")
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)

def load_events(run):
    ev = []
    for line in open(os.path.join(ROOT, "results", run, "falco_events.json"), errors="replace"):
        try: j = json.loads(line)
        except ValueError: continue
        ev.append((ms(j["time"]), j["rule"], str(j.get("output_fields", {}).get("container.name", "")), line))
    return ev

def skew(run, ev):
    """median(rx - evt) from falco_rx.log if present (Falco clock skew, see memory/parsers); else 0."""
    p = os.path.join(ROOT, "results", run, "falco_rx.log")
    d = []
    if os.path.exists(p):
        for line in open(p, errors="replace"):
            a, _, rest = line.partition("\t")
            try: j = json.loads(rest); d.append(int(a) - ms(j["time"]))
            except (ValueError, KeyError): continue
    d.sort()
    return d[len(d) // 2] if d else 0

def recount(run):
    ev = load_events(run); sk = skew(run, ev)
    out = {}
    for r in csv.DictReader(open(os.path.join(ROOT, "results", run, "runs.csv"))):
        t = r["technique"]; vid, grp, want, pats = VAR[t]
        s, e = int(r["start_ms"]), int(r["end_ms"])
        hit = [(ru, c) for (tt, ru, c, l) in ev if s - 2000 <= tt + sk <= e and (c.startswith("falco-lab-") or r["token"] in l)]
        direct = [x for x in hit if any(p in x[0] for p in pats) and x[1].startswith(want)]
        state = "direct" if direct else ("misattrib" if hit else "miss")
        body = open(os.path.join(ROOT, "results", run, f"{t}_{r['rep']}.out"), errors="replace").read()
        ok = r["exit_code"] == "0" and (r["token"] in body or "BENIGN_PIPE_OK" in body)
        o = out.setdefault(vid, {"technique": t, "group": grp, "n": 0, "direct": 0, "misattrib": 0, "miss": 0,
                                 "payload_ok": 0, "rules": set()})
        o["n"] += 1; o[state] += 1; o["payload_ok"] += ok; o["rules"].update(f"{a}@{b}" for a, b in hit)
    return out, len(ev), sk

def state(o):
    for k in ("direct", "misattrib", "miss"):
        if o[k] == o["n"]: return k
    return "mixed"

def main():
    rc = {}
    for k, run in RUNS.items(): rc[k] = recount(run)
    var = {}
    for mode in ("default", "custom"):
        a = dict(rc[mode][0]); a.update(rc[mode + "_dev"][0]); var[mode] = a
    tdir = os.path.join(ROOT, "report", "tables")
    rows = []
    for vid in ["E4-T1b", "E4-T3d", "E4-T2b", "E4-T4b", "E4-T5b", "E4-T5c", "E4-T6b", "DEV-T1r"]:
        d, c = var["default"][vid], var["custom"][vid]
        rows.append({"variant": vid, "technique": d["technique"], "group": d["group"], "class_p0": CLASS[vid][0],
                     "class_note": CLASS[vid][1], "n": d["n"],
                     "default_state": state(d), "default_D/M/X": f"{d['direct']}/{d['misattrib']}/{d['miss']}",
                     "custom_state": state(c), "custom_D/M/X": f"{c['direct']}/{c['misattrib']}/{c['miss']}",
                     "payload_ok_default": d["payload_ok"], "payload_ok_custom": c["payload_ok"],
                     "default_alerts": "; ".join(sorted(d["rules"])), "custom_alerts": "; ".join(sorted(c["rules"]))})
    with open(os.path.join(tdir, "e4_reclassified_variants.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    by = {r["variant"]: r for r in rows}

    def subset(name, ids, definition):
        res = []
        for mode in ("default", "custom"):
            kv = sum(by[i][f"{mode}_state"] == "direct" for i in ids); nv = len(ids)
            kr = sum(int(by[i][f"{mode}_D/M/X"].split("/")[0]) for i in ids); nr = sum(by[i]["n"] for i in ids)
            lo, hi = wilson(kv, nv); rlo, rhi = wilson(kr, nr)
            res.append({"subset": name, "ruleset": mode, "variants": " ".join(ids), "k_variants": kv, "n_variants": nv,
                        "wilson95_lo": f"{lo:.4f}", "wilson95_hi": f"{hi:.4f}", "k_runs": kr, "n_runs": nr,
                        "run_unit_wilson_lo_REFERENCE_ONLY": f"{rlo:.4f}", "run_unit_wilson_hi_REFERENCE_ONLY": f"{rhi:.4f}",
                        "cp_one_sided95_upper_if_k0": (f"{1 - 0.05 ** (1 / nv):.3f}" if kv == 0 and nv else ""),
                        "definition": definition})
        return res
    strict = [v for v, (c, _) in CLASS.items() if c == "strict_unseen"]
    related = [v for v, (c, _) in CLASS.items() if c == "related_unseen"]
    allE4 = ["E4-T1b", "E4-T3d", "E4-T2b", "E4-T4b", "E4-T5b", "E4-T5c", "E4-T6b"]
    S = []
    S += subset("all_E4_held_out", allE4, "all 7 E4 variants (A+B); NOT an unseen claim")
    S += subset("group_A_E4", [v for v in allE4 if by[v]["group"] == "A"], "Group A E4 variants")
    S += subset("related_unseen", related, "E4-T1b, E4-T6b, E4-T5c")
    S += subset("strict_unseen_P0", strict, "PRIMARY: Group A, not syscall-equivalent, not enumerated in any rule draft, no rule added after variant written")
    S += subset("strict_unseen_historical", ["E4-T3d", "E4-T2b", "E4-T4b", "E4-T5b", "E4-T5c"], "HISTORICAL (2026-10-22 report): incl. E4-T5c; superseded")
    S += subset("independent_external", [], "no externally designed variant executed -> NOT TESTED")
    with open(os.path.join(tdir, "e4_reclassified_subsets.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(S[0])); w.writeheader(); w.writerows(S)
    sens = []
    for name, ids in [("strict_P0 (primary)", strict), ("strict incl. E4-T5c (historical)", strict + ["E4-T5c"]),
                      ("strict excl. E4-T2b (conceived pre-freeze)", [v for v in strict if v != "E4-T2b"]),
                      ("strict excl. E4-T2b, incl. E4-T5c", [v for v in strict if v != "E4-T2b"] + ["E4-T5c"])]:
        for mode in ("default", "custom"):
            kv = sum(by[i][f"{mode}_state"] == "direct" for i in ids); lo, hi = wilson(kv, len(ids))
            sens.append({"scenario": name, "ruleset": mode, "variants": " ".join(ids), "k": kv, "n": len(ids),
                         "wilson95": f"[{lo:.2f}, {hi:.2f}]"})
    with open(os.path.join(tdir, "e4_sensitivity.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(sens[0])); w.writeheader(); w.writerows(sens)

    # cross-check vs historical table (read-only)
    bad = 0
    for h in csv.DictReader(open(os.path.join(tdir, "e4_unseen_summary.csv"))):
        r = by[h["tech_id"]]
        for mode, col in (("default", "default_D/M/X/B/E"), ("custom", "custom_D/M/X/B/E")):
            hd = "/".join(h[col].split("/")[:3])
            if h[f"{mode}_state"] != r[f"{mode}_state"] or hd != r[f"{mode}_D/M/X"]:
                bad += 1; print("MISMATCH", h["tech_id"], mode, h[f"{mode}_state"], hd, "vs", r[f"{mode}_state"], r[f"{mode}_D/M/X"])
    for k, run in RUNS.items(): print(f"{run}: events={rc[k][1]} skew_ms={rc[k][2]}")
    for r in rows: print(f"{r['variant']:8} {r['class_p0']:16} default={r['default_state']:9}{r['default_D/M/X']}  custom={r['custom_state']:9}{r['custom_D/M/X']}  ok={r['payload_ok_default']}/{r['payload_ok_custom']}")
    for s in S: print(f"{s['subset']:26} {s['ruleset']:7} {s['k_variants']}/{s['n_variants']}  W95=[{s['wilson95_lo']},{s['wilson95_hi']}]  runs {s['k_runs']}/{s['n_runs']}  cp1={s['cp_one_sided95_upper_if_k0']}")
    for s in sens: print(f"SENS {s['scenario']:44} {s['ruleset']:7} {s['k']}/{s['n']} {s['wilson95']}")
    print("cross-check vs e4_unseen_summary.csv:", "OK" if bad == 0 else f"{bad} MISMATCH")
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
