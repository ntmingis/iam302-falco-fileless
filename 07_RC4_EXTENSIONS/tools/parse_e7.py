#!/usr/bin/env python3
"""parse_e7.py <tool> <e7_out_dir> <e1_run_dir> <out_prefix> — RC4 E7 second-sensor scoring (pre-registered).

Window per runs.csv row = [start_ms, end_ms + 2000]. Event container = container ID (Tetragon process.docker /
Tracee container.id, prefix match) mapped to a name via container_ids.log (sampler, +-5 s). Payload state comes from
parse_e1.py output for the same run (e1_detail.csv 'payload' column): only payload=ok reps are scored.

Pre-registered DIRECT maps (fixed before any E7 run):
 TETRAGON v1.7.1 (base sensor, no TracingPolicy): direct iff a process_exec event in the expected container whose
   process.binary_properties.file.inode.links == 0 (Tetragon's fileless/unlinked-binary indicator). Model coverage:
   memfd, e4_memfd_execveat, dev_memfd_runcname, procfd_drop. All other techniques: NO detection construct in the base
   sensor ("no-model"); scored miss in k/n and labelled no-model.
 TRACEE v0.23.2 signatures:
   fileless_execution  -> memfd, e4_memfd_execveat, dev_memfd_runcname, shm_host, shm_ctr, shm_ctr_exec, e4_shm_argv0
   dropped_executable  -> procfd_drop
   ld_preload          -> preload, e4_preload_env
   ptrace              -> NOT COMPARABLE (lab T7 = PTRACE_ATTACH/DETACH; TRC-103 = POKETEXT/POKEDATA); hits reported only
   all others          -> no signature with matching intent ("no-model"), scored miss in k/n.
Variant state = direct if all payload-ok reps direct; miss if none; mixed otherwise (as e4_reclassify.py).
"""
import csv, json, os, sys
from datetime import datetime, timezone
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rc4stats import fmt

TOOL, OUTD, RUN, PFX = sys.argv[1:5]
EXPECT = {"memfd": "falco-lab-target", "shm_host": None, "shm_ctr": "falco-lab-target", "shm_ctr_exec": "falco-lab-shmexec",
          "procfd_link": "falco-lab-target", "procfd_nolink": "falco-lab-target", "procfd_drop": "falco-lab-target",
          "python": "falco-lab-target", "curl": "falco-lab-client", "preload": "falco-lab-target", "ptrace": "falco-lab-target",
          "dev_memfd_runcname": "falco-lab-target", "e4_memfd_execveat": "falco-lab-target", "e4_procfd_argv0": "falco-lab-target",
          "e4_shm_argv0": "falco-lab-shmexec", "e4_python_stdin": "falco-lab-target", "e4_curl_script": "falco-lab-client",
          "e4_curl_sh": "falco-lab-client", "e4_preload_env": "falco-lab-target"}
VID = {"memfd": "T1", "shm_host": "T2-host", "shm_ctr": "T2-ctr", "shm_ctr_exec": "T2-ctr-exec", "procfd_link": "T3a",
       "procfd_nolink": "T3b", "procfd_drop": "T3c", "python": "T4", "curl": "T5", "preload": "T6", "ptrace": "T7",
       "dev_memfd_runcname": "DEV-T1r", "e4_memfd_execveat": "E4-T1b", "e4_procfd_argv0": "E4-T3d", "e4_shm_argv0": "E4-T2b",
       "e4_python_stdin": "E4-T4b", "e4_curl_script": "E4-T5b", "e4_curl_sh": "E4-T5c", "e4_preload_env": "E4-T6b"}
TG_COVER = {"memfd", "e4_memfd_execveat", "dev_memfd_runcname", "procfd_drop"}
TR_MAP = {**{t: "fileless_execution" for t in ("memfd", "e4_memfd_execveat", "dev_memfd_runcname", "shm_host", "shm_ctr",
                                               "shm_ctr_exec", "e4_shm_argv0")},
          "procfd_drop": "dropped_executable", "preload": "ld_preload", "e4_preload_env": "ld_preload"}
NOT_COMPARABLE = {"tracee": {"ptrace"}, "tetragon": set()}


def iso_ms(s):
    b, _, f = s.rstrip("Z").partition(".")
    return int(datetime.fromisoformat(b).replace(tzinfo=timezone.utc).timestamp() * 1000) + int((f + "000")[:3])


ids = []
for l in open(os.path.join(OUTD, "container_ids.log"), errors="replace"):
    p = l.split()
    if len(p) == 3: ids.append((int(p[0]), p[1], p[2]))


def cname(cid, ms):
    if not cid: return None
    for t, full, name in ids:
        if abs(t - ms) <= 5000 and full.startswith(cid[:12]): return name
    return "?"


ev = []  # (ms, kind, container_name, is_direct_marker_by_family)
if TOOL == "tetragon":
    for l in open(os.path.join(OUTD, "tetragon_events.json"), errors="replace"):
        try: e = json.loads(l)
        except ValueError: continue
        pe = e.get("process_exec")
        if not pe: continue
        pr = pe.get("process", {}); ms = iso_ms(e["time"])
        links = (((pr.get("binary_properties") or {}).get("file") or {}).get("inode") or {}).get("links")
        fl = (pr.get("binary_properties") or {}).get("file") is not None and int(links or 0) == 0
        ev.append((ms, "fileless_indicator" if fl else "process_exec", cname(pr.get("docker", ""), ms), pr.get("binary", "")))
else:
    for l in open(os.path.join(OUTD, "tracee_rx.log"), errors="replace"):
        ms, _, js = l.partition("\t")
        try: e = json.loads(js)
        except ValueError: continue
        c = e.get("container") or {}
        ev.append((int(ms), e.get("eventName", ""), c.get("name") or cname(c.get("id", ""), int(ms)), e.get("processName", "")))

payload = {}
for r in csv.DictReader(open(os.path.join(RUN, "e1_detail.csv"))):
    payload[r["token"]] = r["payload"]
rows, per = [], {}
for r in csv.DictReader(open(os.path.join(RUN, "runs.csv"))):
    t, tok = r["technique"], r["token"]; s, e = int(r["start_ms"]), int(r["end_ms"]) + 2000
    want = EXPECT[t]
    win = [x for x in ev if s <= x[0] <= e and ((x[2] == want) if want else (x[2] in (None, "", "?")))]
    sig = [x for x in win if x[1] not in ("process_exec",)] if TOOL == "tetragon" else win
    if TOOL == "tetragon":
        d = [x for x in win if x[1] == "fileless_indicator"] if t in TG_COVER else []
        model = "covered" if t in TG_COVER else "no-model"
    else:
        d = [x for x in win if x[1] == TR_MAP.get(t)]
        model = "not-comparable" if t in NOT_COMPARABLE["tracee"] else ("covered" if t in TR_MAP else "no-model")
    pl = payload.get(tok, "?")
    st = ("direct" if d else ("other-signal" if sig else "miss")) if pl == "ok" else pl
    rows.append([TOOL, VID[t], t, r["rep"], tok, pl, model, st, "|".join(sorted({x[1] for x in sig}))])
    per.setdefault(t, []).append(st)
summ = []
k = n = 0
for t, sts in per.items():
    okr = [x for x in sts if x in ("direct", "other-signal", "miss")]
    model = next(r[6] for r in rows if r[2] == t)
    if not okr: vs = sts[0] if len(set(sts)) == 1 else "mixed-nonok"
    else: vs = "direct" if all(x == "direct" for x in okr) else ("miss" if not any(x == "direct" for x in okr) else "mixed")
    if okr and model == "covered": n += 1; k += vs == "direct"  # headline denominator = variants the tool's model can detect (no-model reported separately)
    summ.append([TOOL, VID[t], t, model, vs, f"{sum(x=='direct' for x in sts)}/{len(okr)}"])
nm=sum(1 for t,sts in per.items() if next(r[6] for r in rows if r[2]==t)=="no-model"); summ.append([TOOL, "COVERED variants (headline)", "", f"no-model={nm}", fmt(k, n), ""])
with open(PFX + "_detail.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["tool", "variant", "technique", "rep", "token", "payload", "model", "state", "signals_in_window"]); w.writerows(rows)
with open(PFX + "_summary.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["tool", "variant", "technique", "model", "variant_state", "direct_reps/ok_reps"]); w.writerows(summ)
for r in summ: print(",".join(map(str, r)))
