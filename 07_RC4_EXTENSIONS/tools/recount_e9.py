#!/usr/bin/env python3
"""recount_e9.py <e1_run_dir> <proc_map.tsv> — INDEPENDENT E9 recount (no import of parse_e1/parse_e9_altscope).
For each payload-ok window, counts whether a matching audit SYSCALL record exists under (rc3) subj=docker-default and
(alt) pid->ppid lineage reaching a falco-lab-* container init/shim PID from the proc_map. Hand-rolled record grouping,
independent hex-decoding argv matcher; prints recalls. Matches the scorer's intended quantity by identity, not value."""
import csv, os, re, sys

RUN, PMAP = sys.argv[1], sys.argv[2]
KEY = {"memfd": "fileless_memfd", "dev_memfd_runcname": "fileless_memfd"}
ATOK = {"python", "curl", "procfd_nolink"}
AEXE = {"python": '/usr/local/bin/python3', "curl": '/usr/bin/curl'}  # exe pattern like parse_e1.APAT
txt = open(os.path.join(RUN, "audit.log"), errors="replace").read()

recs = {}
for line in txt.splitlines():
    m = re.search(r"audit\((\d+)\.(\d+):(\d+)\)", line)
    if not m:
        continue
    r = recs.setdefault(m.group(3), {"ms": int(m.group(1)) * 1000 + int(m.group(2)), "t": ""})
    r["t"] += line + "\n"

pm = []
for l in open(PMAP):
    f = l.rstrip().split("\t")
    if len(f) >= 4 and f[2].isdigit():
        pm.append((int(f[0]), f[1], int(f[2]), int(f[3]) if f[3].isdigit() else -1))

parent = {}
for r in recs.values():
    mm = re.search(r"type=SYSCALL .*? ppid=(\d+) pid=(\d+)", r["t"])
    if mm:
        parent[int(mm.group(2))] = int(mm.group(1))

ARG = re.compile(r' a\d+=(?:"([^"]*)"|([0-9A-Fa-f]+))')


def argv_has(rtext, tok):
    for line in rtext.splitlines():
        if "type=EXECVE" not in line:
            continue
        for q, h in ARG.findall(line):
            val = bytes.fromhex(h).decode(errors="replace") if h else q
            if tok in val:
                return True
    return False


def lineage_ok(r):
    mm = re.search(r"type=SYSCALL .*? ppid=(\d+) pid=(\d+)", r["t"])
    if not mm:
        return False
    roots = {}
    for ms, c, ip, sp in pm:
        if abs(ms - r["ms"]) <= 10000 and c.startswith("falco-lab-"):
            roots[ip] = 1
            roots[sp] = 1
    p, h = int(mm.group(2)), 0
    while p and h < 25:
        if p in roots:
            return True
        p = parent.get(p, 0)
        h += 1
    return False


rc3 = alt = n = 0
for row in csv.DictReader(open(os.path.join(RUN, "runs.csv"))):
    t = row["technique"]
    if int(row["exit_code"]) != 0:
        continue
    s, e, key = int(row["start_ms"]) - 1000, int(row["end_ms"]), KEY.get(t, "fileless_exec")
    n += 1
    r3 = a = False
    for r in recs.values():
        if not (s <= r["ms"] <= e) or f'key="{key}"' not in r["t"] or "success=no" in r["t"]:
            continue
        if t in ATOK and not argv_has(r["t"], row["token"]):
            continue
        if "subj=docker-default" in r["t"]:
            r3 = True
        if lineage_ok(r):
            a = True
    rc3 += r3
    alt += a
print(f"{RUN}: payload-ok windows={n} rc3_specific={rc3} alt_specific={alt}")
