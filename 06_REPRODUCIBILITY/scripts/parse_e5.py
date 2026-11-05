#!/usr/bin/env python3
"""parse_e5.py v1 - python3 parse_e5.py results/e5_<time> [out_dir]
Tong hop e5_runs.csv theo (config, part): n, median/p95 runtime, overhead % so voi 'none'
  (= (median_cfg - median_none) / median_none * 100), CPU host trung binh/dinh, CPU-giay + RSS cua falco/auditd,
  audit lost tong va backlog toi da. Chi so mo ta: n nho (REPS), khong tuyen bo y nghia thong ke."""
import csv, os, statistics, sys
from collections import defaultdict

RUN = sys.argv[1].rstrip("/"); OUT = sys.argv[2].rstrip("/") if len(sys.argv) > 2 else RUN
rows = list(csv.DictReader(open(f"{RUN}/e5_runs.csv")))
g = defaultdict(list)
for r in rows: g[(r["config"], r["part"])].append(r)
def col(rs, k): return [float(r[k]) for r in rs if r[k] not in ("", None)]
def med(v): return round(statistics.median(v), 2) if v else ""
def p95(v): v = sorted(v); return round(v[min(len(v) - 1, int(.95 * len(v)))], 2) if v else ""
base = {p: statistics.median(col(rs, "runtime_ms")) for (c, p), rs in g.items() if c == "none" and col(rs, "runtime_ms")}
os.makedirs(OUT, exist_ok=True)
hdr = ["config", "part", "n", "n_failed", "runtime_ms_median", "runtime_ms_p95", "runtime_overhead_pct_vs_none",
       "cpu_avg_pct_median", "cpu_peak_pct_max", "falco_cpu_s_median", "auditd_cpu_s_median",
       "falco_rss_kb_max", "auditd_rss_kb_max", "audit_lost_sum", "audit_backlog_max"]
order = {"none": 0, "falco": 1, "auditd": 2, "both": 3}
with open(f"{OUT}/e5_overhead_summary.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(hdr)
    for (c, p), rs in sorted(g.items(), key=lambda kv: (kv[0][1], order.get(kv[0][0], 9))):
        rt = col(rs, "runtime_ms"); m = statistics.median(rt) if rt else None
        w.writerow([c, p, len(rs), sum(r["exit_code"] != "0" for r in rs), med(rt), p95(rt),
                    round((m - base[p]) / base[p] * 100, 1) if m is not None and p in base and c != "none" else "",
                    med(col(rs, "cpu_avg_pct")), max(col(rs, "cpu_peak_pct"), default=""),
                    med(col(rs, "falco_cpu_s")), med(col(rs, "auditd_cpu_s")),
                    int(max(col(rs, "falco_rss_kb"), default=0)), int(max(col(rs, "auditd_rss_kb"), default=0)),
                    int(sum(col(rs, "audit_lost_delta"))), int(max(col(rs, "audit_backlog_end"), default=0))])
print(open(f"{OUT}/e5_overhead_summary.csv").read())
