#!/usr/bin/env python3
"""parse_e8.py <run_dir>... -> rc4/tables/e8_results_rc4.csv, e8_variant_summary_rc4.csv (independent_external)

Pre-registered (fixed with e8_selection.csv, before any E8 run). Window = [start_ms, end_ms + 2000] on host receipt
time (falco_rx.log). An alert counts only if container.name == the row's container.
DIRECT map by family (substring of rule name):
  memfd        : "Fileless execution via memfd_create", "LAB memfd exec masquerading", "LAB2 memfd exec covered"
  devshm       : "Execution from /dev/shm", "LAB2 Exec from /dev/shm"
  pipe-to-shell: "LAB Download piped", "LAB Shell reading", "LAB2 Shell reading", "LAB2 Downloader writing"
  interpreter  : "LAB Interpreter inline", "LAB2 Interpreter reading"
  ld-preload   : "LAB Process started with LD_PRELOAD"
Payload: ok iff exit 0 (T1059.006#4: 0 or 124 = timeout of the interactive pty, accepted as executed);
  devshm: 'blocked' if the target's /dev/shm mount is noexec (event-generator returns 0 on EACCES/126).
Variant state per condition: direct if all payload-ok reps direct; miss if none; mixed otherwise; blocked/error if no
payload-ok rep. Primary k/n = primary_fileless=yes variants; k = #direct; Wilson 95 % (+ CP one-sided upper for k=0).
Out-of-family variants: reported as any-alert counts only (never in k/n). Never merged with E4.
"""
import csv, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rc4stats import fmt
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
FAM = {"memfd": ["Fileless execution via memfd_create", "LAB memfd exec masquerading", "LAB2 memfd exec covered"],
       "devshm": ["Execution from /dev/shm", "LAB2 Exec from /dev/shm"],
       "pipe-to-shell": ["LAB Download piped", "LAB Shell reading", "LAB2 Shell reading", "LAB2 Downloader writing"],
       "interpreter": ["LAB Interpreter inline", "LAB2 Interpreter reading"],
       "ld-preload": ["LAB Process started with LD_PRELOAD"]}
sel = {r["test_id"]: r for r in csv.DictReader(open(os.path.join(ROOT, "rc4/tables/e8_selection.csv")))}
detail, summ = [], []
for run in sys.argv[1:]:
    cond = os.path.basename(run.rstrip("/")).split("_")[1]
    rx = []
    for l in open(os.path.join(run, "falco_rx.log"), errors="replace"):
        ms, _, js = l.partition("\t")
        try: e = json.loads(js)
        except ValueError: continue
        rx.append((int(ms), e.get("rule", ""), (e.get("output_fields") or {}).get("container.name") or ""))
    noexec = "noexec" in open(os.path.join(run, "target_devshm_mount.txt")).read()
    per = {}
    for r in csv.DictReader(open(os.path.join(run, "runs.csv"))):
        t = r["test_id"]; s = sel[t]; fam = s["family"]; rc = int(r["exit_code"])
        win = [x for x in rx if int(r["start_ms"]) <= x[0] <= int(r["end_ms"]) + 2000 and x[2] == r["container"]]
        d = [x for x in win if any(p in x[1] for p in FAM.get(fam, []))]
        ok = rc == 0 or (t == "T1059.006#4" and rc == 124)
        pl = "blocked" if (fam == "devshm" and noexec) else ("ok" if ok else "error")
        st = ("direct" if d else ("misattrib" if win else "miss")) if pl == "ok" else pl
        detail.append([cond, t, r["rep"], r["container"], rc, pl, st, len(win), "|".join(sorted({x[1] for x in win}))])
        per.setdefault(t, []).append(st)
    k = n = 0
    for t, sts in per.items():
        okr = [x for x in sts if x in ("direct", "misattrib", "miss")]
        vs = (sts[0] if len(set(sts)) == 1 else "mixed") if not okr else \
             ("direct" if all(x == "direct" for x in okr) else ("miss" if not any(x == "direct" for x in okr) else "mixed"))
        prim = sel[t]["primary_fileless"] == "yes"
        if prim and okr: n += 1; k += vs == "direct"
        summ.append([cond, t, sel[t]["family"], "primary" if prim else "secondary", vs,
                     f"{sum(x=='direct' for x in sts)}/{sum(x=='misattrib' for x in sts)}/{sum(x=='miss' for x in sts)}/{sum(x not in ('direct','misattrib','miss') for x in sts)}"])
    summ.append([cond, "PRIMARY k/n", "", "independent_external", fmt(k, n), ""])
with open(os.path.join(ROOT, "rc4/tables/e8_results_rc4.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["condition", "test_id", "rep", "container", "exit", "payload", "state", "alerts_in_window", "rules"]); w.writerows(detail)
with open(os.path.join(ROOT, "rc4/tables/e8_variant_summary_rc4.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["condition", "test_id", "family", "subset", "variant_state", "D/M/X/other"]); w.writerows(summ)
for r in summ: print(",".join(map(str, r)))
