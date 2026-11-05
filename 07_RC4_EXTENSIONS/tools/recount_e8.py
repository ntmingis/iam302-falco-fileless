#!/usr/bin/env python3
"""recount_e8.py <run_dir>... — INDEPENDENT E8 recount (no import of parse_e8.py). Re-derives primary k/n (direct
variants among primary_fileless=yes) per condition by a hand-rolled window scan of falco_rx.log. Family direct-rule
map is re-stated here independently."""
import csv, json, os, re, sys
ROOT=os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),"..",".."))
sel={r["test_id"]:r for r in csv.DictReader(open(os.path.join(ROOT,"rc4/tables/e8_selection.csv")))}
FAM={"memfd":["Fileless execution via memfd_create","LAB memfd exec masquerading","LAB2 memfd exec covered"],
 "devshm":["Execution from /dev/shm","LAB2 Exec from /dev/shm"],
 "pipe-to-shell":["LAB Download piped","LAB Shell reading","LAB2 Shell reading","LAB2 Downloader writing"],
 "interpreter":["LAB Interpreter inline","LAB2 Interpreter reading"],
 "ld-preload":["LAB Process started with LD_PRELOAD"]}
def wilson(k,n,z=1.96):
    import math
    if n==0: return (float('nan'),)*2
    p=k/n; d=1+z*z/n; c=(p+z*z/(2*n))/d; h=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d; return max(0,c-h),min(1,c+h)
for run in sys.argv[1:]:
    cond=os.path.basename(run).split("_")[1]
    rx=[]
    for l in open(os.path.join(run,"falco_rx.log"),errors="replace"):
        ms,_,js=l.partition("\t")
        try:e=json.loads(js)
        except:continue
        rx.append((int(ms),e.get("rule",""),(e.get("output_fields") or {}).get("container.name") or ""))
    noexec="noexec" in open(os.path.join(run,"target_devshm_mount.txt")).read()
    per={}
    for r in csv.DictReader(open(os.path.join(run,"runs.csv"))):
        t=r["test_id"]; fam=sel[t]["family"]; rc=int(r["exit_code"])
        ok = rc==0 or (t=="T1059.006#4" and rc==124)
        if fam=="devshm" and noexec: st="blocked"
        elif not ok: st="error"
        else:
            win=[x for x in rx if int(r["start_ms"])<=x[0]<=int(r["end_ms"])+2000 and x[2]==r["container"]]
            st="direct" if any(any(p in x[1] for p in FAM.get(fam,[])) for x in win) else "miss"
        per.setdefault(t,[]).append(st)
    k=n=0
    for t,sts in per.items():
        okr=[x for x in sts if x in ("direct","miss")]
        if sel[t]["primary_fileless"]=="yes" and okr:
            n+=1; k+= all(x=="direct" for x in okr)
    lo,hi=wilson(k,n)
    print(f"{cond}: primary direct k/n = {k}/{n} Wilson [{lo:.2f},{hi:.2f}]")
