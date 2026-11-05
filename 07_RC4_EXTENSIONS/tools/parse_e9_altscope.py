#!/usr/bin/env python3
"""parse_e9_altscope.py <e1_run_dir> <proc_map.tsv> <out_csv> — RC4 E9 alternative Auditd container scoping.

Pre-registered (fixed before any E9 data was seen). parse_e1.py is NOT edited: it is imported read-only for its
audit loader, argv decoder, key/pattern maps and payload_state, so the ONLY difference between the two scorings is the
container test:
  RC3 proxy   : record text contains 'subj=docker-default'                         (parse_e1.audit_state)
  ALT scoping : the record's process lineage (pid -> ppid, built from the SYSCALL records of the same audit.log) reaches
                the init PID or the containerd-shim PID of a running falco-lab-* container, as captured from /proc at
                run time by rc4/runs/e9_proc_sampler.sh (sample within +-10 s of the record). The sampler also logs the
                container init's pid-namespace inode and cgroup for reference.
Everything else (key, exe/comm pattern, success=no -> blocked, token-in-argv) is identical to parse_e1.audit_state.
Output columns: technique, rep, token, payload, auditd_rc3, auditd_alt, alt_container_evidence.
"""
import csv, os, re, sys
from collections import defaultdict

RUN, PMAP, OUT = sys.argv[1].rstrip("/"), sys.argv[2], sys.argv[3]
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, ROOT)
sys.argv = [sys.argv[0], RUN, os.path.dirname(OUT) or "."]
import parse_e1 as P  # noqa: E402  (module-level code only sets paths/maps; main() is guarded)

SYS_RE = re.compile(r"type=SYSCALL .*? ppid=(\d+) pid=(\d+)")


def load_pmap(p):
    pm = []  # (ms, container, init_pid, shim_pid)
    for l in open(p):
        f = l.rstrip("\n").split("\t")
        if len(f) < 5 or not f[2].isdigit() or f[2] == "0": continue
        pm.append((int(f[0]), f[1], int(f[2]), int(f[3]) if f[3].isdigit() else -1))
    return pm


def main():
    recs = P.load_audit()
    parent = {}
    for r in recs:
        for m in SYS_RE.finditer(r["text"]):
            parent[int(m.group(2))] = int(m.group(1))
    pm = load_pmap(PMAP)

    def in_ctr(r):
        m = SYS_RE.search(r["text"])
        if not m: return False, ""
        roots = {}
        for ms, c, ip, sp in pm:
            if abs(ms - r["ms"]) <= 10000 and c.startswith("falco-lab-"):
                roots[ip] = f"{c}:init"; roots[sp] = f"{c}:shim"
        p, hops = int(m.group(2)), 0
        while p and hops < 25:
            if p in roots: return True, roots[p]
            p = parent.get(p, 0); hops += 1
        return False, ""

    def alt_state(t, tok, s, e):
        key = P.AKEY.get(t, "fileless_exec"); pat = P.APAT.get(t)
        ok, failed, ev = [], False, ""
        for r in recs:
            if not (s - 1000 <= r["ms"] <= e) or f'key="{key}"' not in r["text"]: continue
            ctr, why = in_ctr(r)
            if (t == "shm_host") == ctr: continue
            if pat and not re.search(pat, r["text"]): continue
            if "success=no" in r["text"]: failed = True; continue
            if t in P.ATOK and tok not in P.argv(r["text"]): continue
            ok.append(ctr); ev = ev or why
        return ("specific" if ok else "miss"), failed, ev

    rows = []
    for r in csv.DictReader(open(f"{RUN}/runs.csv")):
        t, tok, s, e, rc = r["technique"], r["token"], int(r["start_ms"]), int(r["end_ms"]), int(r["exit_code"])
        a1, _, f1 = P.audit_state(t, tok, recs, s, e)
        a2, f2, ev = alt_state(t, tok, s, e)
        pl = P.payload_state(t, tok, rc, r["rep"], f1 or f2)
        if pl != "ok": a1 = a2 = pl
        rows.append([t, r["rep"], tok, pl, a1, a2, ev])
    with open(OUT, "w", newline="") as f:
        w = csv.writer(f); w.writerow(["technique", "rep", "token", "payload", "auditd_rc3", "auditd_alt", "alt_container_evidence"])
        w.writerows(rows)
    print(f"{len(rows)} rows -> {OUT}")


if __name__ == "__main__":
    main()
