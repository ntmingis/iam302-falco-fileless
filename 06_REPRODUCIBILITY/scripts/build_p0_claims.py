#!/usr/bin/env python3
"""build_p0_claims.py - claim -> evidence table for the P0 report (Appendix D / Bang 17). Added 2026-11-04 (post-audit remediation).

Why: Appendix D of FINAL_REPORT_P0_REVISED was rendered from report/tables/claim_evidence.csv, which is the
2026-11-02 (pre-P0) table: it states strict-unseen = 2/5 as VERIFIED and calls 1/4 a "sensitivity" row. That
contradicts the P0 primary result. claim_evidence.csv is kept byte-identical (it is the source of the preserved
2026-11-02 revised report); this script writes a separate P0 table:

  report/tables/claim_evidence_p0.csv

Rules
  - Claims C01-C07, C13, C15, C18-C29 are carried over from claim_evidence.csv only if their status there is VERIFIED.
  - All E4 claims (C08-C12, C14, C16, C17 + historical rows) are recomputed from the P0 tables:
      e4_reclassified_subsets.csv (k/n and Wilson columns), e4_reclassified_variants.csv (per-variant class + state,
      recounted independently), e4_sensitivity.csv (printed Wilson strings), and tablestats.wilson (recomputed CI).
  - A row is VERIFIED only if the value printed in the report == the recomputed value AND every cross-check agrees.
    Otherwise MISMATCH, and the script exits 1.
  - role: PRIMARY | HISTORICAL-SENSITIVITY | REFERENCE_ONLY | CONTEXT.
Reads only report/tables/*.csv; writes only claim_evidence_p0.csv. No raw data is read or changed.
Run from the project root: python3 report/tools/build_p0_claims.py"""
import csv, os, sys
sys.path.insert(0, os.getcwd())
from tablestats import wilson

T = "report/tables"
OUT = f"{T}/claim_evidence_p0.csv"
def rd(n): return list(csv.DictReader(open(f"{T}/{n}")))

old = {c["claim_id"]: c for c in rd("claim_evidence.csv")}
sub = {(x["subset"], x["ruleset"]): x for x in rd("e4_reclassified_subsets.csv")}
var = rd("e4_reclassified_variants.csv")
sens = {(x["scenario"], x["ruleset"]): x for x in rd("e4_sensitivity.csv")}

def kn(subset, rs): x = sub[(subset, rs)]; return f'{x["k_variants"]}/{x["n_variants"]}'
def kn_runs(subset, rs): x = sub[(subset, rs)]; return f'{x["k_runs"]}/{x["n_runs"]}'
def wil(k, n): lo, hi = wilson(k, n); return f"{lo:.2f}–{hi:.2f}"
def wil_csv(subset, rs, lo="wilson95_lo", hi="wilson95_hi"):
    x = sub[(subset, rs)]; return f"{float(x[lo]):.2f}–{float(x[hi]):.2f}"
def sens_str(scn, rs):  # "[0.05, 0.70]" -> "0.05–0.70"
    return sens[(scn, rs)]["wilson95"].strip("[]").replace(", ", "–")
def sens_kn(scn, rs): x = sens[(scn, rs)]; return f'{x["k"]}/{x["n"]}'
def recount(classes, rs, exclude=(), include=()):
    """independent recount from the per-variant classification table"""
    ids = [v["variant"] for v in var if v["class_p0"] in classes and v["variant"] not in exclude] + list(include)
    st = {v["variant"]: v[f"{rs}_state"] for v in var}
    return f"{sum(st[i] == 'direct' for i in ids)}/{len(ids)}"

STRICT_HIST = ("E4-T5c",)  # historical strict set = P0 strict + E4-T5c
held_out = [v["variant"] for v in var if v["variant"].startswith("E4-")]
def recount_ids(ids, rs):
    st = {v["variant"]: v[f"{rs}_state"] for v in var}
    return f"{sum(st[i] == 'direct' for i in ids)}/{len(ids)}"

# (id, claim, role, reported_in_report, recomputed, source, [cross-check values that must equal recomputed])
e4 = [
    ("C08", "E4 toàn bộ 7 biến thể giữ lại, default (KHÔNG phải claim unseen)", "CONTEXT", "1/7",
     kn("all_E4_held_out", "default"), "e4_reclassified_subsets.csv all_E4_held_out",
     [recount_ids(held_out, "default")]),
    ("C09", "E4 toàn bộ 7 biến thể giữ lại, custom (KHÔNG phải claim unseen)", "CONTEXT", "4/7",
     kn("all_E4_held_out", "custom"), "e4_reclassified_subsets.csv all_E4_held_out",
     [recount_ids(held_out, "custom")]),
    ("C10", "E4 giữ lại, custom: tập biến thể direct", "CONTEXT", "E4-T1b E4-T3d E4-T5c E4-T6b",
     " ".join(v["variant"] for v in var if v["variant"].startswith("E4-") and v["custom_state"] == "direct"),
     "e4_reclassified_variants.csv", []),
    ("C11", "E4 strict-unseen P0 (4 biến thể), default — kết quả CHÍNH", "PRIMARY", "0/4",
     kn("strict_unseen_P0", "default"), "e4_reclassified_subsets.csv strict_unseen_P0",
     [recount({"strict_unseen"}, "default"), sens_kn("strict_P0 (primary)", "default")]),
    ("C12", "E4 strict-unseen P0 (4 biến thể), custom — kết quả CHÍNH", "PRIMARY", "1/4",
     kn("strict_unseen_P0", "custom"), "e4_reclassified_subsets.csv strict_unseen_P0",
     [recount({"strict_unseen"}, "custom"), sens_kn("strict_P0 (primary)", "custom")]),
    ("C14", "Wilson 95% (biến thể) strict-unseen P0 custom 1/4 — CHÍNH", "PRIMARY", "0.05–0.70",
     wil(1, 4), "tablestats.wilson(1,4)",
     [wil_csv("strict_unseen_P0", "custom"), sens_str("strict_P0 (primary)", "custom")]),
    ("C14b", "Wilson 95% (biến thể) strict-unseen P0 default 0/4 — CHÍNH", "PRIMARY", "0.00–0.49",
     wil(0, 4), "tablestats.wilson(0,4)",
     [wil_csv("strict_unseen_P0", "default"), sens_str("strict_P0 (primary)", "default")]),
    ("C16", "Wilson 95% (lần chạy) strict P0 custom 5/20 — KHÔNG dùng làm khoảng chính", "REFERENCE_ONLY", "0.11–0.47",
     wil(5, 20), "tablestats.wilson(5,20)",
     [wil_csv("strict_unseen_P0", "custom", "run_unit_wilson_lo_REFERENCE_ONLY", "run_unit_wilson_hi_REFERENCE_ONLY"),
      "0.11–0.47" if kn_runs("strict_unseen_P0", "custom") == "5/20" else kn_runs("strict_unseen_P0", "custom")]),
    ("C17", "Strict-unseen custom: 1/4 là kết quả CHÍNH (E4-T5c = related-unseen, bị loại)", "PRIMARY", "1/4",
     recount({"strict_unseen"}, "custom"), "e4_reclassified_variants.csv class_p0 (đếm lại)",
     [kn("strict_unseen_P0", "custom")]),
    ("C17h", "Độ nhạy LỊCH SỬ (định nghĩa 2026-10-22, gồm E4-T5c, 5 biến thể), custom — không phải kết quả chính",
     "HISTORICAL-SENSITIVITY", "2/5",
     kn("strict_unseen_historical", "custom"), "e4_reclassified_subsets.csv strict_unseen_historical",
     [recount({"strict_unseen"}, "custom", include=STRICT_HIST), sens_kn("strict incl. E4-T5c (historical)", "custom")]),
    ("C17h-d", "Độ nhạy LỊCH SỬ (gồm E4-T5c, 5 biến thể), default", "HISTORICAL-SENSITIVITY", "0/5",
     kn("strict_unseen_historical", "default"), "e4_reclassified_subsets.csv strict_unseen_historical",
     [recount({"strict_unseen"}, "default", include=STRICT_HIST), sens_kn("strict incl. E4-T5c (historical)", "default")]),
    ("C17h-w", "Wilson 95% (biến thể) độ nhạy LỊCH SỬ custom 2/5", "HISTORICAL-SENSITIVITY", "0.12–0.77",
     wil(2, 5), "tablestats.wilson(2,5)",
     [wil_csv("strict_unseen_historical", "custom"), sens_str("strict incl. E4-T5c (historical)", "custom")]),
]
E4_IDS = {"C08", "C09", "C10", "C11", "C12", "C14", "C16", "C17"}
ROLE = {"C13": "CONTEXT", "C15": "REFERENCE_ONLY"}
# carried-over rows whose pre-P0 wording would read as an unseen claim: relabel the text only (values unchanged)
RELABEL = {"C13": "Wilson 95% (biến thể) toàn bộ 7 biến thể giữ lại, custom 4/7 (KHÔNG phải claim unseen)",
           "C15": "Wilson 95% (lần chạy) toàn bộ giữ lại 20/35 — KHÔNG dùng làm khoảng chính (lặp xác định)"}

rows, bad = [], 0
for cid, c in old.items():
    if cid in E4_IDS: continue
    ok = c["status"] == "VERIFIED" and c["reported"] == c["recomputed"]
    rows.append([cid, RELABEL.get(cid, c["claim"]), ROLE.get(cid, "PRIMARY"), c["reported"], c["recomputed"], c["source"],
                 "carried over from claim_evidence.csv (recomputed there from CSV)", "VERIFIED" if ok else "MISMATCH"])
    bad += not ok
for cid, claim, role, rep, got, src, checks in e4:
    agree = all(x == got for x in checks)
    ok = rep == got and agree
    rows.append([cid, claim, role, rep, got, src, "; ".join(checks) if checks else "-", "VERIFIED" if ok else "MISMATCH"])
    if not ok:
        bad += 1; print(f"MISMATCH {cid}: report={rep} recomputed={got} cross-checks={checks}", file=sys.stderr)

def key(r):
    import re
    m = re.match(r"C(\d+)(.*)", r[0]); return (int(m.group(1)), m.group(2))
rows.sort(key=key)
with open(OUT, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["claim_id", "claim", "role", "reported", "recomputed", "source", "cross_check_values", "status"])
    w.writerows(rows)
print(f"{OUT}: {len(rows)} claims, {bad} mismatch")
sys.exit(1 if bad else 0)
