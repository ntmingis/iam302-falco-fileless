#!/usr/bin/env python3
"""recount_e6.py <e1_run_dir> — INDEPENDENT recount of E6 community-direct (no import of parse_e6.py).
Re-derives, per technique window, the count of COMMUNITY-rule alerts that are the pre-registered DIRECT rule for that
technique's family (only the download family has one: 'Launch Ingress Remote File Copy Tools in Container' for
curl/e4_curl_script/e4_curl_sh) firing on the expected container. Prints per-variant community_direct and a total; a
nonzero community_direct for any variant would refute the 'no additional direct detection' prediction."""
import csv, json, os, re, sys
RUN=sys.argv[1]
UP=os.path.join(os.path.dirname(os.path.abspath(__file__)),"..","..","experiments","E6_community_ruleset","upstream")
comm=set()
for f in ("falco-incubating-rules-6.0.1.yaml","falco-sandbox-rules-6.2.0.yaml"):
    for l in open(os.path.join(UP,f)):
        m=re.match(r"^- rule:\s*(.+?)\s*$",l)
        if m: comm.add(m.group(1).strip().strip('"').strip("'"))
EXPECT={"memfd":"falco-lab-target","shm_host":None,"shm_ctr":"falco-lab-target","shm_ctr_exec":"falco-lab-shmexec","procfd_link":"falco-lab-target","procfd_nolink":"falco-lab-target","procfd_drop":"falco-lab-target","python":"falco-lab-target","curl":"falco-lab-client","preload":"falco-lab-target","ptrace":"falco-lab-target","dev_memfd_runcname":"falco-lab-target","e4_memfd_execveat":"falco-lab-target","e4_procfd_argv0":"falco-lab-target","e4_shm_argv0":"falco-lab-shmexec","e4_python_stdin":"falco-lab-target","e4_curl_script":"falco-lab-client","e4_curl_sh":"falco-lab-client","e4_preload_env":"falco-lab-target"}
DIRECT={t:"Launch Ingress Remote File Copy Tools in Container" for t in ("curl","e4_curl_script","e4_curl_sh")}
rx=[]
for l in open(os.path.join(RUN,"falco_rx.log"),errors="replace"):
    ms,_,js=l.partition("\t")
    try:e=json.loads(js)
    except:continue
    rx.append((int(ms),e.get("rule",""),(e.get("output_fields") or {}).get("container.name") or ""))
tot=0; per={}
for r in csv.DictReader(open(os.path.join(RUN,"runs.csv"))):
    t=r["technique"]; s=int(r["start_ms"]); e=int(r["end_ms"])+2000; want=EXPECT.get(t)
    cd=[x for x in rx if s<=x[0]<=e and x[1] in comm and t in DIRECT and x[1]==DIRECT[t] and (want is None or x[2]==want)]
    per[t]=per.get(t,0)+len(cd); tot+=len(cd)
for t in sorted(per): 
    if per[t]: print(f"{t}: community_direct={per[t]}")
print(f"TOTAL community_direct across all variants = {tot} (community rule names loaded: {len(comm)})")
