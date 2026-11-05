#!/usr/bin/env python3
"""build_tables.py - gop analysis/<run>/ thanh bang bao cao trong report/tables/.
Chi doc output parser (e1_summary.csv, e2_summary.csv, e5_overhead_summary.csv); khong doc lai log tho.
Danh sach run duoc chon co chu dich (RUNS) - pilot/probe KHONG duoc gop.
  python3 build_tables.py"""
import csv, os, statistics
from collections import defaultdict
from tablestats import coverage, wilson

A = "analysis"; OUT = "report/tables"
RUNS = {
    "e1_default": "e1_default_20261021_001604",
    "e1_custom": "e1_custom_20261021_010337",          # Falco hop le; Auditd r2-5 mat snapshot (xem current_audit.md)
    # 2026-10-22: parse lai cung run voi audit.log hop nhat (snapshot goc + ban sao journald cho rep 2-5),
    #   tools_supp/recover_audit_journal.py; Falco giong het e1_custom. Dung cho cot Auditd/T2-ctr cua E3.
    "e1_custom_auditrec": "e1_custom_20261021_010337_auditrecovered",
    "e1_custom_all_t3": "e1_custom_20261021_013127_all_t3",
    "e4_default": "e1_default_20261021_002936_e4",
    "e4_custom": "e1_custom_20261021_011709_e4",
    "dev_default": "e1_default_20261021_005859_dev",
    "dev_custom": "e1_custom_20261021_012554_dev",
    "e2_default": "e2_default_20261021_010013",
    "e2_custom": "e2_custom_20261021_012710",
    "e5": "e5_20261021_013631",
    # E2 bo sung 2026-10-22 (run_e2_supp.sh): PostgreSQL 14 that + build gcc/make that; khong thay the run E2 cu
    "e2supp_default": "e2supp_default_20261022_110425",
    "e2supp_custom": "e2supp_custom_20261022_110602",
}
NOTES_E3 = {"T2-ctr": "custom: exit 126 cả 5/5; rep 2–5 xác nhận success=no từ bản sao journald (ban đầu 4 'error' do snapshot audit mất)",
            "T1": "LAB Interpreter inline code đồng bắn do harness nạp payload bằng python3 -c",
            "T7": "LAB Interpreter inline code đồng bắn do harness nạp payload bằng python3 -c"}
def rd(run, f): return list(csv.DictReader(open(f"{A}/{run}/{f}")))
def wr(name, hdr, rows):
    with open(f"{OUT}/{name}", "w", newline="") as f: w = csv.writer(f); w.writerow(hdr); w.writerows(rows)
    print(f"{OUT}/{name}: {len(rows)} dong")
def state(x):  # trang thai Falco chiem uu the + dem day du
    c = {k: int(x[k]) for k in ("falco_direct", "falco_misattrib", "falco_miss", "blocked", "error")}
    top = max(c, key=c.get).replace("falco_", "")
    return top, f"{c['falco_direct']}/{c['falco_misattrib']}/{c['falco_miss']}/{c['blocked']}/{c['error']}"
def rules(x): return x["rules@container"].replace("|", "; ")

os.makedirs(OUT, exist_ok=True)

# ---- E1 (default, REPS=5)
e1 = rd(RUNS["e1_default"], "e1_summary.csv")
wr("e1_summary.csv", ["run_id", "tech_id", "group", "n", "payload_ok", "falco_state", "D/M/X/B/E",
                      "auditd_specific", "auditd_container_proxy", "pipeline_p50_ms", "pipeline_p95_ms",
                      "e2e_upper_p95_ms", "audit_lost_sum", "rules@container"],
   [[RUNS["e1_default"], x["tech_id"], x["group"], x["n"], x["payload_ok"], *state(x), x["auditd_specific"],
     x["auditd_container"], x["pipeline_p50"], x["pipeline_p95"], x["e2e_p95"], x["audit_lost_sum"], rules(x)]
    for x in e1])

# ---- E3 default vs custom(first) vs custom(all, chi T3)
cu = {x["tech_id"]: x for x in rd(RUNS["e1_custom_auditrec"], "e1_summary.csv")}
cu0 = {x["tech_id"]: x for x in rd(RUNS["e1_custom"], "e1_summary.csv")}
for t, x in cu.items():  # Falco phai giong het parse goc (chi khac T2-ctr: error -> blocked nho audit phuc hoi)
    assert t == "T2-ctr" or state(x) == state(cu0[t]), t
al = {x["tech_id"]: x for x in rd(RUNS["e1_custom_all_t3"], "e1_summary.csv")}
rows = []
for x in e1:
    t = x["tech_id"]; c = cu[t]; a = al.get(t)
    rows.append([t, x["group"], x["n"], *state(x), c["n"], *state(c), *(state(a) if a else ("", "")),
                 rules(x), rules(c), rules(a) if a else "", NOTES_E3.get(t, ""),
                 x["auditd_specific"], c["auditd_specific"]])
wr("e3_comparison.csv", ["tech_id", "group", "n_default", "default_state", "default_D/M/X/B/E",
                         "n_custom_first", "custom_first_state", "custom_first_D/M/X/B/E",
                         "custom_all_state", "custom_all_D/M/X/B/E", "rules_default", "rules_custom_first",
                         "rules_custom_all", "note", "auditd_specific_default", "auditd_specific_custom"], rows)

# ---- E4 unseen (+ DEV tach rieng, set=DEV khong tinh vao ty le unseen)
# strict = nhom A, khong tuong duong ky thuat E1 da dung de viet rule o muc syscall (E4-T1b = execveat nhu T1)
E4_INDEP = {"E4-T1b": ("equiv_T1", "tương đương T1 ở mức syscall (execveat 322); không tính là bằng chứng tổng quát hoá"),
            "E4-T3d": ("strict", "cùng họ T3 (exec /proc/self/fd/N), argv0 khác; rule custom bắt theo evt.arg.filename"),
            "E4-T2b": ("strict", "rule default dùng proc.exe (argv0) → exec -a kworker vượt qua"),
            "E4-T4b": ("strict", "code qua stdin, argv không có -c → rule dựa argv không thấy"),
            "E4-T5b": ("strict", "pipeline nằm trong file script → pcmdline của cha là 'bash /tmp/dl.sh'"),
            "E4-T5c": ("strict", "cùng họ T5 (curl | sh thay vì | bash); rule custom đã liệt kê '| sh'"),
            "E4-T6b": ("group_B", "nhóm B (injection-related), không thuộc tập fileless"),
            "DEV-T1r": ("dev", "DEV: dùng khi thiết kế rule, không tính unseen")}
rows = []
for setname, dk, ck in (("UNSEEN", "e4_default", "e4_custom"), ("DEV", "dev_default", "dev_custom")):
    cc = {x["tech_id"]: x for x in rd(RUNS[ck], "e1_summary.csv")}
    for x in rd(RUNS[dk], "e1_summary.csv"):
        c = cc[x["tech_id"]]
        rows.append([setname, x["tech_id"], x["group"], x["technique"], x["n"], *state(x), *state(c),
                     x["auditd_specific"], c["auditd_specific"], rules(c), *E4_INDEP[x["tech_id"]]])
hdr = ["set", "tech_id", "group", "technique", "n", "default_state", "default_D/M/X/B/E",
       "custom_state", "custom_D/M/X/B/E", "auditd_specific_default", "auditd_specific_custom", "rules_custom",
       "subset", "independence_note"]
wr("e4_unseen_summary.csv", hdr, rows)
e4d = [dict(zip(hdr, r)) for r in rows]
cov = []
for name, sel, desc in (("full_unseen", lambda r: r["set"] == "UNSEEN", "toàn bộ 7 biến thể E4 gốc (A+B, gồm E4-T1b)"),
                        ("group_A_unseen", lambda r: r["set"] == "UNSEEN" and r["group"] == "A", "nhóm A, gồm E4-T1b"),
                        ("strict_A_independent", lambda r: r["subset"] == "strict", "nhóm A, bỏ E4-T1b (≡T1) và nhóm B"),
                        ("group_B_unseen", lambda r: r["set"] == "UNSEEN" and r["group"] == "B", "nhóm B (E4-T6b)")):
    sub = [r for r in e4d if sel(r)]
    for rs in ("default", "custom"):
        kv, nv, kr, nr = coverage(sub, f"{rs}_state", f"{rs}_D/M/X/B/E"); lo, hi = wilson(kv, nv)
        cov.append([name, rs, " ".join(r["tech_id"] for r in sub), kv, nv, kr, nr, round(lo, 4), round(hi, 4), desc])
wr("e4_coverage.csv", ["subset", "ruleset", "variants", "variants_direct", "variants_n", "runs_direct", "runs_n",
                       "wilson95_lo_variants", "wilson95_hi_variants", "definition"], cov)

# ---- E2 FP theo workload x ruleset. Run goc (2026-10-21) giu nguyen ten workload; run bo sung doi ten workload
#   de khong trung (db_*, sql_postgres, build_gcc). duration_s = tong thoi luong cac cua so (e2_runs.csv).
SUPP_WL = {"lifecycle_up": "db_lifecycle_up", "sql": "sql_postgres", "build": "build_gcc", "lifecycle_down": "db_lifecycle_down"}
DETAIL = {"lifecycle_up": "run -d nginx (db_mode=none)", "http": "curl nội bộ tới nginx", "build": "artifact: cp /bin/true → chạy (không có gcc)",
          "python": "script file, -m json.tool, -c", "churn": "docker run --rm ubuntu true", "lifecycle_down": "stop/rm nginx",
          "db_lifecycle_up": "run -d PostgreSQL 14.24 + pg_isready", "sql_postgres": "psql: CREATE/INSERT 1000/INDEX/UPDATE/SELECT",
          "build_gcc": "gcc 11.4 + make: 2 file .c → link → chạy app", "db_lifecycle_down": "stop/rm PostgreSQL"}
rows = []
for k in ("e2_default", "e2_custom", "e2supp_default", "e2supp_custom"):
    supp = k.startswith("e2supp")
    dur = defaultdict(float)
    for r in csv.DictReader(open(f"results/{RUNS[k]}/e2_runs.csv")):
        dur[r["workload"]] += (int(r["end_ms"]) - int(r["start_ms"])) / 1000
    for x in rd(RUNS[k], "e2_summary.csv"):
        if x["workload"] in ("", "background_alerts"): continue
        wl = SUPP_WL[x["workload"]] if supp else x["workload"]
        rows.append([k.split("_")[1], RUNS[k], wl, x["windows"], x["units_ok"], x["fp_alerts"],
                     x["fp_windows"], x["fp_window_rate"], x["wilson95_lo"].replace("-0.0", "0.0"),
                     x["wilson95_hi"], x["rule_of_three_hi"], x["fp_rules"], x["auditd_memfd_ctr"],
                     x["auditd_exec_ctr"], "supp_20261022" if supp else "orig_20261021", round(dur[x["workload"]], 1), DETAIL[wl]])
wr("e2_fp_summary.csv", ["ruleset", "run_id", "workload", "windows", "units_ok", "fp_alerts", "fp_windows",
                         "fp_window_rate", "wilson95_lo", "wilson95_hi", "rule_of_three_hi", "fp_rules",
                         "auditd_memfd_ctr", "auditd_exec_ctr", "phase", "duration_s", "workload_detail"], rows)

# ---- E5 overhead + khoang min-max runtime (de thay su chong lan voi baseline)
g = defaultdict(list)
for r in csv.DictReader(open(f"{A}/{RUNS['e5']}/e5_runs_normalized.csv")):
    g[(r["config"], r["part"])].append(float(r["runtime_ms"]))
base = {p: (min(v), max(v)) for (c, p), v in g.items() if c == "none"}
rows = []
for x in rd(RUNS["e5"], "e5_overhead_summary.csv"):
    v = g[(x["config"], x["part"])]; b = base[x["part"]]
    overlap = "" if x["config"] == "none" else ("yes" if min(v) <= b[1] and max(v) >= b[0] else "no")
    rows.append([x[k] for k in x] + [int(min(v)), int(max(v)), overlap])
wr("e5_overhead_summary.csv", list(rd(RUNS["e5"], "e5_overhead_summary.csv")[0].keys())
   + ["runtime_ms_min", "runtime_ms_max", "range_overlaps_none"], rows)

with open(f"{OUT}/SOURCES.txt", "w") as f:
    f.write("".join(f"{k}={v}\n" for k, v in RUNS.items()))
