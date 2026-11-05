#!/usr/bin/env python3
"""recount_e7.py <tool> <e7_dir> <e1_dir> — INDEPENDENT E7 recount (no import of parse_e7.py).
Re-derives direct k/n over comparable variants by a hand-rolled window scan. Tetragon: direct iff a process_exec with
binary_properties.file.inode.links==0 in the expected container. Tracee: direct iff the pre-registered signature name
fires in the expected container. Payload-ok from e1_detail.csv. T7 excluded for tracee (not comparable)."""
import csv, json, os, sys
from datetime import datetime, timezone
TOOL, OUTD, RUN = sys.argv[1], sys.argv[2], sys.argv[3]
EXPECT = {"memfd":"falco-lab-target","shm_host":None,"shm_ctr":"falco-lab-target","shm_ctr_exec":"falco-lab-shmexec","procfd_link":"falco-lab-target","procfd_nolink":"falco-lab-target","procfd_drop":"falco-lab-target","python":"falco-lab-target","curl":"falco-lab-client","preload":"falco-lab-target","ptrace":"falco-lab-target","dev_memfd_runcname":"falco-lab-target","e4_memfd_execveat":"falco-lab-target","e4_procfd_argv0":"falco-lab-target","e4_shm_argv0":"falco-lab-shmexec","e4_python_stdin":"falco-lab-target","e4_curl_script":"falco-lab-client","e4_curl_sh":"falco-lab-client","e4_preload_env":"falco-lab-target"}
TG_COVER={"memfd","e4_memfd_execveat","dev_memfd_runcname","procfd_drop"}
TR={**{t:"fileless_execution" for t in ("memfd","e4_memfd_execveat","dev_memfd_runcname","shm_host","shm_ctr","shm_ctr_exec","e4_shm_argv0")},"procfd_drop":"dropped_executable","preload":"ld_preload","e4_preload_env":"ld_preload"}
def iso(s):
    b,_,f=s.rstrip("Z").partition("."); return int(datetime.fromisoformat(b).replace(tzinfo=timezone.utc).timestamp()*1000)+int((f+"000")[:3])
ids=[]
for l in open(os.path.join(OUTD,"container_ids.log"),errors="replace"):
    p=l.split()
    if len(p)==3: ids.append((int(p[0]),p[1],p[2]))
def cname(cid,ms):
    if not cid: return None
    for t,full,name in ids:
        if abs(t-ms)<=5000 and full.startswith(cid[:12]): return name
    return "?"
ev=[]
if TOOL=="tetragon":
    for l in open(os.path.join(OUTD,"tetragon_events.json"),errors="replace"):
        try:e=json.loads(l)
        except:continue
        pe=e.get("process_exec")
        if not pe: continue
        pr=pe.get("process",{}); ms=iso(e["time"])
        bp=(pr.get("binary_properties") or {}).get("file") or {}
        links=(bp.get("inode") or {}).get("links")
        ev.append((ms,"fileless" if (bp and int(links or 0)==0) else "exec",cname(pr.get("docker",""),ms)))
else:
    for l in open(os.path.join(OUTD,"tracee_rx.log"),errors="replace"):
        ms,_,js=l.partition("\t")
        try:e=json.loads(js)
        except:continue
        c=e.get("container") or {}
        ev.append((int(ms),e.get("eventName",""),c.get("name") or cname(c.get("id",""),int(ms))))
pay={r["token"]:r["payload"] for r in csv.DictReader(open(os.path.join(RUN,"e1_detail.csv")))}
per={}
for r in csv.DictReader(open(os.path.join(RUN,"runs.csv"))):
    t,tok=r["technique"],r["token"]; s,e=int(r["start_ms"]),int(r["end_ms"])+2000; want=EXPECT[t]
    win=[x for x in ev if s<=x[0]<=e and ((x[2]==want) if want else x[2] in (None,"","?"))]
    if TOOL=="tetragon":
        comp = t in TG_COVER; d=[x for x in win if x[1]=="fileless"] if comp else []
    else:
        comp = t in TR and t!="ptrace"; d=[x for x in win if x[1]==TR.get(t)] if comp else []
        if t=="ptrace": comp=False
    st=("direct" if d else "miss") if pay.get(tok)=="ok" else pay.get(tok,"?")
    per.setdefault(t,[]).append((comp,st))
import math
k=n=0
for t,v in per.items():
    comp=v[0][0]; okr=[s for _,s in v if s in ("direct","miss")]
    if comp and okr:
        n+=1; k+= all(s=="direct" for s in okr)
def wil(k,n,z=1.96):
    if n==0: return (float('nan'),)*2
    p=k/n; d=1+z*z/n; c=(p+z*z/(2*n))/d; h=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d; return max(0,c-h),min(1,c+h)
lo,hi=wil(k,n); print(f"{TOOL}: comparable direct k/n = {k}/{n} Wilson [{lo:.2f},{hi:.2f}]")
