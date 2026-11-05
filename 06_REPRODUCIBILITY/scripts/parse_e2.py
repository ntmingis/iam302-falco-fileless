#!/usr/bin/env python3
"""parse_e2.py v1 - python3 parse_e2.py results/e2_<ruleset>_<time> [out_dir]
E2 false-positive baseline. Moi Falco alert duoc quy ve:
  fp          = trong cua so workload VA (container cua chinh workload do, hoac tien trinh runtime
                runc/containerd/dockerd tren host) -> workload LANH TINH kich hoat alert = false positive
  background  = ngoai cua so workload, hoac host khong phai runtime (vd. pkexec/polkit) -> khong tinh FP
Mau so: units (so lan thuc hien workload) va windows (so lan goi workload); khoang tin cay Wilson 95%
  cho ti le windows co >=1 FP; khi 0 FP -> can tren 'rule of three' 3/n.
Auditd khong phat alert: dem ban ghi key fileless_memfd/fileless_ptrace (subj=docker-default) trong cua so
  workload = tin hieu se thanh FP NEU dung key do lam detector; fileless_exec chi la khoi luong telemetry.
Lech dong ho Falco/host: hieu chinh nhu parse_e1.py (median rx - evt, nguong 1000 ms)."""
import csv, glob, json, math, os, re, statistics, sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

RUN = sys.argv[1].rstrip("/")
OUT = sys.argv[2].rstrip("/") if len(sys.argv) > 2 else RUN
FALCO = f"{RUN}/falco_events.json" if os.path.exists(f"{RUN}/falco_events.json") else "/var/log/falco/events.json"
AUDIT = f"{RUN}/audit.log" if os.path.exists(f"{RUN}/audit.log") else "/var/log/audit/audit.log*"
RULESET = "default"
try:
    for l in open(f"{RUN}/versions.txt"):
        if l.startswith("ruleset="): RULESET = l.split("=", 1)[1].strip()
except OSError: pass

# container cua tung workload (tien to ten)
WCONT = {"lifecycle_up": ("falco-lab-e2-web", "falco-lab-e2-db"), "lifecycle_down": ("falco-lab-e2-web", "falco-lab-e2-db"),
         "http": ("falco-lab-client", "falco-lab-e2-web"), "sql": ("falco-lab-e2-db",),
         "build": ("falco-lab-e2-build-",), "python": ("falco-lab-target",), "churn": ("falco-lab-e2-churn-",)}
RUNTIME = {"runc", "containerd", "containerd-shim", "containerd-shim-runc-v2", "dockerd", "docker", "docker-init", "docker-proxy"}

def fts(s):
    b, _, f = s.rstrip("Z").partition(".")
    return int(datetime.fromisoformat(b).replace(tzinfo=timezone.utc).timestamp() * 1000) + int((f + "000")[:3])

def load_falco():
    try: lines = open(FALCO, errors="replace")
    except PermissionError:
        print(f"[!] khong doc duoc {FALCO} -> dung falco_rx.log", file=sys.stderr)
        lines = (l.partition("\t")[2] for l in open(f"{RUN}/falco_rx.log", errors="replace"))
    ev = []
    for l in lines:
        try: j = json.loads(l)
        except ValueError: continue
        o = j.get("output_fields", {})
        ev.append({"ms": fts(j["time"]), "time": j["time"], "rule": j.get("rule", ""), "prio": j.get("priority", ""),
                   "cont": str(o.get("container.name", "")), "proc": str(o.get("proc.name", "")),
                   "pname": str(o.get("proc.pname", "")), "cmd": str(o.get("proc.cmdline", ""))[:160]})
    return ev

def load_rx():
    rx = {}
    try:
        for l in open(f"{RUN}/falco_rx.log", errors="replace"):
            t, _, js = l.partition("\t")
            try: j = json.loads(js)
            except ValueError: continue
            rx.setdefault((j["time"], j.get("rule", "")), int(t))
    except OSError: pass
    return rx

A_RE = re.compile(r"msg=audit\((\d+)\.(\d+):(\d+)\)")
K_RE = re.compile(r'key="(fileless_\w+)"')
def load_audit():
    rec = {}
    for p in sorted(glob.glob(AUDIT)):
        for l in open(p, errors="replace"):
            m = A_RE.search(l)
            if not m: continue
            r = rec.setdefault(m.group(3), {"ms": int(m.group(1)) * 1000 + int(m.group(2)), "key": None, "ctr": False})
            k = K_RE.search(l)
            if k: r["key"] = k.group(1); r["ctr"] = "subj=docker-default" in l
    return [r for r in rec.values() if r["key"]]

def wilson(k, n, z=1.96):
    if n == 0: return ("", "")
    p = k / n; d = 1 + z * z / n; c = p + z * z / (2 * n); h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (round((c - h) / d, 4), round((c + h) / d, 4))

def main():
    runs = list(csv.DictReader(open(f"{RUN}/e2_runs.csv")))
    fev, rx, aud = load_falco(), load_rx(), load_audit()
    d = sorted(rx[(x["time"], x["rule"])] - x["ms"] for x in fev if (x["time"], x["rule"]) in rx)
    skew = statistics.median(d) if d else 0
    if abs(skew) > 1000:
        for x in fev: x["ms"] += round(skew)
        print(f"[!] lech dong ho Falco/host = {skew:.0f} ms (n={len(d)}) -> da hieu chinh", file=sys.stderr)
    os.makedirs(OUT, exist_ok=True)
    wins = [(r["workload"], int(r["round"]), int(r["start_ms"]), int(r["end_ms"]), int(r["exit_code"]), int(r["units"])) for r in runs]
    t0, t1 = min(w[2] for w in wins), max(w[3] for w in wins)

    alerts = []
    for x in fev:
        if not (t0 - 1000 <= x["ms"] <= t1 + 1000): continue
        w = next((w for w in wins if w[2] - 500 <= x["ms"] <= w[3]), None)
        own = w and x["cont"].startswith(WCONT[w[0]])
        rt = w and x["cont"] == "host" and (x["proc"] in RUNTIME or x["pname"] in RUNTIME)
        cls = "fp" if (own or rt) else "background"
        alerts.append([x["time"], x["rule"], x["prio"], x["cont"], x["proc"], x["pname"], x["cmd"],
                       w[0] if w else "", w[1] if w else "", cls])
    with open(f"{OUT}/e2_alerts.csv", "w", newline="") as f:
        cw = csv.writer(f); cw.writerow(["time", "rule", "priority", "container", "proc", "pname", "cmdline", "workload", "round", "class"])
        cw.writerows(alerts)

    by = defaultdict(list)
    for w in wins: by[w[0]].append(w)
    rows = []
    for wl, ws in by.items():
        fa = [a for a in alerts if a[7] == wl and a[9] == "fp"]
        fpw = {(a[7], a[8]) for a in fa}
        n = len(ws); units = sum(w[5] for w in ws if w[4] == 0); k = len(fpw)
        au = Counter(r["key"] for r in aud for w in ws if w[2] <= r["ms"] <= w[3] and r["ctr"])
        lo, hi = wilson(k, n)
        rows.append([wl, n, sum(w[4] != 0 for w in ws), units, len(fa), k, round(k / n, 4) if n else "", lo, hi,
                     round(3 / n, 4) if k == 0 and n else "", round(len(fa) / units, 5) if units else "",
                     "|".join(f"{r}={c}" for r, c in Counter(a[1] for a in fa).most_common()),
                     au.get("fileless_memfd", 0), au.get("fileless_ptrace", 0), au.get("fileless_exec", 0)])
    bg = Counter(a[1] for a in alerts if a[9] == "background")
    hdr = ["workload", "windows", "windows_failed", "units_ok", "fp_alerts", "fp_windows", "fp_window_rate", "wilson95_lo",
           "wilson95_hi", "rule_of_three_hi", "fp_alerts_per_unit", "fp_rules", "auditd_memfd_ctr", "auditd_ptrace_ctr", "auditd_exec_ctr"]
    with open(f"{OUT}/e2_summary.csv", "w", newline="") as f:
        cw = csv.writer(f); cw.writerow(hdr); cw.writerows(rows)
        cw.writerow([]); cw.writerow(["background_alerts", sum(bg.values()), "|".join(f"{r}={c}" for r, c in bg.most_common())])
    with open(f"{OUT}/parse_meta.txt", "w") as f:
        f.write(f"run={RUN}\nruleset={RULESET}\nfalco_src={FALCO}\naudit_src={AUDIT}\nclock_skew_ms={skew:.0f}\n"
                f"skew_corrected={abs(skew) > 1000}\nalerts_in_span={len(alerts)}\n")
    print(f"ruleset={RULESET} -> {OUT}/e2_summary.csv"); print(open(f"{OUT}/e2_summary.csv").read())

if __name__ == "__main__": main()
