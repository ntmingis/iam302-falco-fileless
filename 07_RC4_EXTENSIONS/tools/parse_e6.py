#!/usr/bin/env python3
"""parse_e6.py <e1_run_dir> <out_csv> — RC4 E6-dynamic community attribution (pre-registered, new parser variant).

Does NOT replace parse_e1.py: parse_e1.py (unchanged) gives payload state + base-map direct detection. This script
adds, per (technique, rep) window from runs.csv, the alerts of COMMUNITY rules (rule names defined in the pinned
incubating-6.0.1 / sandbox-6.2.0 files) received (falco_rx.log host clock) in [start_ms, end_ms + 2000].

Pre-registered community DIRECT map (intent-matched, fixed before any E6 data was seen):
  curl, e4_curl_script, e4_curl_sh -> "Launch Ingress Remote File Copy Tools in Container" (download family)
  every other technique            -> none (no community rule has a matching documented intent)
community_direct = a mapped rule fires on the expected container; community_other = any other community-rule alert
in the window (misattrib for scoring). Static prediction per variant is CONFIRMED iff community_direct == 0/n.
"""
import csv, json, os, re, sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
UP = os.path.join(ROOT, "experiments", "E6_community_ruleset", "upstream")
EXPECT = {"memfd": "falco-lab-target", "shm_host": None, "shm_ctr": "falco-lab-target", "shm_ctr_exec": "falco-lab-shmexec",
          "procfd_link": "falco-lab-target", "procfd_nolink": "falco-lab-target", "procfd_drop": "falco-lab-target",
          "python": "falco-lab-target", "curl": "falco-lab-client", "preload": "falco-lab-target", "ptrace": "falco-lab-target",
          "dev_memfd_runcname": "falco-lab-target", "e4_memfd_execveat": "falco-lab-target", "e4_procfd_argv0": "falco-lab-target",
          "e4_shm_argv0": "falco-lab-shmexec", "e4_python_stdin": "falco-lab-target", "e4_curl_script": "falco-lab-client",
          "e4_curl_sh": "falco-lab-client", "e4_preload_env": "falco-lab-target"}
COMM_DIRECT = {t: ["Launch Ingress Remote File Copy Tools in Container"] for t in ("curl", "e4_curl_script", "e4_curl_sh")}


def community_rules():
    names = set()
    for f in ("falco-incubating-rules-6.0.1.yaml", "falco-sandbox-rules-6.2.0.yaml"):
        for l in open(os.path.join(UP, f), encoding="utf-8"):
            m = re.match(r"^- rule:\s*(.+?)\s*$", l)
            if m: names.add(m.group(1).strip().strip('"').strip("'"))
    return names


def main(run, out):
    comm = community_rules()
    rx = []
    for l in open(os.path.join(run, "falco_rx.log"), encoding="utf-8", errors="replace"):
        ms, _, js = l.partition("\t")
        try: e = json.loads(js)
        except ValueError: continue
        o = e.get("output_fields") or {}
        rx.append((int(ms), e.get("rule", ""), o.get("container.name") or ""))
    rows = []
    for r in csv.DictReader(open(os.path.join(run, "runs.csv"))):
        s, e, t = int(r["start_ms"]), int(r["end_ms"]) + 2000, r["technique"]
        win = [x for x in rx if s <= x[0] <= e and x[1] in comm]
        want = EXPECT.get(t)
        cd = [x for x in win if x[1] in COMM_DIRECT.get(t, []) and (want is None or x[2] == want)]
        co = [x for x in win if x not in cd]
        rows.append([t, r["rep"], r["token"], len(cd), len(co), "|".join(sorted({x[1] for x in cd})),
                     "|".join(sorted({f"{x[1]}@{x[2]}" for x in co}))])
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["technique", "rep", "token", "community_direct_alerts", "community_other_alerts",
                    "community_direct_rules", "community_other_rules"])
        w.writerows(rows)
    print(f"{len(rows)} windows; community rule names loaded: {len(comm)} -> {out}")


if __name__ == "__main__":
    if len(sys.argv) != 3: print(__doc__); sys.exit(2)
    main(sys.argv[1], sys.argv[2])
