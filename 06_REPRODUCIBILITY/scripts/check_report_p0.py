#!/usr/bin/env python3
"""check_report_p0.py - kiem tra report/FINAL_REPORT_P0_REVISED.{pdf,docx} (ban P0). Exit 1 neu co FAIL.
Goc: ban sao cua check_report_revised.py (2026-11-02). 2026-11-04 (remediation sau audit): doi chieu claim_evidence_p0.csv;
kiem SO LIEU E4 (dem lai doc lap tu e4_reclassified_variants.csv + tablestats.wilson) va vai tro PRIMARY/LICH SU,
tung o cua bang Phu luc D trong DOCX, dinh nghia E7-E9 so voi experiments/PLANNED_E7_E8_E9.md, Phu luc C trich build_report_p0.sh,
cach dien dat proc.name (H-07) va chuoi repository chuan - khong chi kiem status == VERIFIED.
Kiem: so trang, trang trang, font nhung + khong co font thay the ngoai Liberation, ky tu loi (U+FFFD),
chu tran le phai/duoi, caption Hinh/Bang du so va cung trang voi hinh/bang, so lieu chinh khop CSV.
Can: pdfinfo, pdffonts, pdftotext, pdfimages, pdftoppm (poppler-utils)."""
import csv, glob, os, re, subprocess, sys, tempfile, zipfile
import matplotlib.image as mpimg

PDF, DOCX, T = "report/FINAL_REPORT_P0_REVISED.pdf", "report/FINAL_REPORT_P0_REVISED.docx", "report/tables"
fails, warns = [], []
def sh(*a): return subprocess.run(a, capture_output=True, text=True, check=True).stdout
def ok(c, msg, warn=False):
    print(("PASS " if c else ("WARN " if warn else "FAIL ")) + msg)
    if not c: (warns if warn else fails).append(msg)

info = sh("pdfinfo", PDF); pages = int(re.search(r"Pages:\s+(\d+)", info).group(1))
pw, ph = map(float, re.search(r"Page size:\s+([\d.]+) x ([\d.]+)", info).groups())
ok(5 <= pages <= 40, f"so trang = {pages}")

fonts = sh("pdffonts", PDF).splitlines()[2:]
ok(all(" yes " in l for l in fonts), f"{len(fonts)} font deu nhung")
odd = [l.split()[0] for l in fonts if not re.search(r"Liberation|DejaVu|OpenSymbol", l)]
ok(not odd, "khong co font thay the la: " + (", ".join(odd) or "-"))

txt = [sh("pdftotext", "-layout", "-f", str(p), "-l", str(p), PDF, "-") for p in range(1, pages + 1)]
alltxt = "\n".join(txt)
ok("�" not in alltxt, "khong co ky tu loi U+FFFD")
for w in ("Abstract", "Tóm tắt", "Related Work", "Evasion Layers and Root Causes", "Limitations", "Responsible Disclosure", "AI Usage Declaration", "Artifact Manifest", "Kết luận", "Phụ lục"):
    ok(w in alltxt, f"tieng Viet hien dung: '{w}'")

with tempfile.TemporaryDirectory() as d:
    sh("pdftoppm", "-r", "30", "-png", PDF, f"{d}/p")
    for f in sorted(glob.glob(f"{d}/p-*.png")):
        a = mpimg.imread(f); ink = 1 - a[..., :3].mean(); pno = int(re.search(r"-(\d+)\.png$", f).group(1))
        ok(ink > 0.006, f"trang {pno} khong trang (ink={ink:.3f})")

# chu tran le: tu nao vuot qua le phai/duoi (le 2 cm = 56.7 pt, du sai 4 pt)
bbox = sh("pdftotext", "-bbox", PDF, "-")
over = []; pg = 0
for l in bbox.splitlines():
    if "<page " in l: pg += 1
    m = re.search(r'xMin="([\d.]+)" yMin="([\d.]+)" xMax="([\d.]+)" yMax="([\d.]+)">([^<]*)<', l)
    if m and (float(m.group(3)) > pw - 52 or float(m.group(4)) > ph - 20):
        over.append(f"tr.{pg}:{m.group(5)[:30]}")
ok(not over, "khong co chu tran le" + ("" if not over else ": " + "; ".join(over[:6])))

# caption
z = zipfile.ZipFile(DOCX); doc = z.read("word/document.xml").decode()
nfig = len(re.findall(r"SEQ Hình", doc)); ntab = len(re.findall(r"SEQ Bảng", doc))
nimg = len([n for n in z.namelist() if n.startswith("word/media/")])
ok(nfig == nimg, f"{nfig} caption Hinh = {nimg} anh trong DOCX")
imgpages = {}
for l in sh("pdfimages", "-list", PDF).splitlines()[2:]:
    p = int(l.split()[0]); imgpages[p] = imgpages.get(p, 0) + 1
for kind, n in (("Hình", nfig), ("Bảng", ntab)):
    for i in range(1, n + 1):
        pat = re.compile(r"^\s*" + kind + " " + str(i) + r"\.\s", re.M)
        pgs = [p + 1 for p, t in enumerate(txt) if pat.search(t)]
        ok(len(pgs) >= 1, f"{kind} {i} co caption trong PDF (trang {pgs})")
        if kind == "Hình" and pgs:
            ok(pgs[0] in imgpages, f"Hình {i}: caption cung trang voi anh (trang {pgs[0]})")
        if kind == "Bảng" and pgs:  # caption bang khong duoc la dong cuoi trang (bang mo coi)
            t = txt[pgs[0] - 1].rstrip().splitlines()
            idx = max(k for k, s in enumerate(t) if pat.search(s + " "))
            ok(len(t) - idx > 3, f"Bảng {i}: caption khong mo coi o cuoi trang {pgs[0]}")

# so lieu khop CSV
def rd(p): return list(csv.DictReader(open(p)))
e1 = rd(f"{T}/e1_summary.csv"); e4 = rd(f"{T}/e4_unseen_summary.csv"); e2 = rd(f"{T}/e2_fp_summary.csv")
aud = sum(int(x["auditd_specific"]) for x in e1); pay = sum(int(x["payload_ok"]) for x in e1)
u_c = sum(x["custom_state"] == "direct" for x in e4 if x["set"] == "UNSEEN")
u_d = sum(x["default_state"] == "direct" for x in e4 if x["set"] == "UNSEEN")
flat = re.sub(r"\s+", " ", alltxt)
# P0: primary strict subset = reclassified strict_unseen_P0 (1/4 custom, 0/4 default).
rsub = {(x["subset"], x["ruleset"]): x for x in rd(f"{T}/e4_reclassified_subsets.csv")}
st = lambda r: f'{rsub[("strict_unseen_P0", r)]["k_variants"]}/{rsub[("strict_unseen_P0", r)]["n_variants"]}'
ok(st("custom") == "1/4" and st("default") == "0/4", f"strict P0 custom={st('custom')} default={st('default')}")
for s in (f"{aud}/{pay}", f"default {u_d}/7", f"custom {u_c}/7", f"default {st('default')}, custom {st('custom')}"):
    ok(s.replace(" ", "") in flat.replace(" ", ""), f"so lieu '{s}' co trong PDF va khop CSV")
for x in e1:
    ok(x["tech_id"] in flat, f"ky thuat {x['tech_id']} co trong PDF")
P0C = rd(f"{T}/claim_evidence_p0.csv")
for c in P0C:
    ok(c["status"] == "VERIFIED", f"claim {c['claim_id']} VERIFIED trong claim_evidence_p0.csv")
    ok(re.sub(r"[\s,]", "", c["recomputed"]) in re.sub(r"[\s,]", "", flat), f"claim {c['claim_id']} = '{c['recomputed']}' co trong PDF")

# ---- 2026-11-04 remediation: numeric + source-table consistency (not only status == VERIFIED) ----
sys.path.insert(0, os.getcwd())
from tablestats import wilson
def wfmt(k, n): lo, hi = wilson(k, n); return f"{lo:.2f}–{hi:.2f}"
var = rd(f"{T}/e4_reclassified_variants.csv")
strict = [v for v in var if v["class_p0"] == "strict_unseen"]
k_c = sum(v["custom_state"] == "direct" for v in strict); k_d = sum(v["default_state"] == "direct" for v in strict)
pc = {c["claim_id"]: c for c in P0C}
EXPECT = {"C11": (f"{k_d}/{len(strict)}", "PRIMARY"), "C12": (f"{k_c}/{len(strict)}", "PRIMARY"),
          "C14": (wfmt(k_c, len(strict)), "PRIMARY"), "C14b": (wfmt(k_d, len(strict)), "PRIMARY"),
          "C17": (f"{k_c}/{len(strict)}", "PRIMARY"),
          "C17h": (st_h := f'{rsub[("strict_unseen_historical", "custom")]["k_variants"]}/{rsub[("strict_unseen_historical", "custom")]["n_variants"]}', "HISTORICAL-SENSITIVITY")}
for cid, (val, role) in EXPECT.items():
    got = pc.get(cid, {})
    ok(got.get("recomputed") == val and got.get("reported") == val, f"claim {cid}: gia tri {got.get('recomputed')!r} == tinh lai doc lap {val!r}")
    ok(got.get("role") == role, f"claim {cid}: vai tro {got.get('role')!r} == {role!r}")
ok((k_c, k_d, len(strict)) == (1, 0, 4), f"E4 strict P0 dem lai tu e4_reclassified_variants = custom {k_c}/{len(strict)}, default {k_d}/{len(strict)}")
hist_vals = {f'{rsub[("strict_unseen_historical", r)]["k_variants"]}/{rsub[("strict_unseen_historical", r)]["n_variants"]}' for r in ("custom", "default")}
bad_primary = [c["claim_id"] for c in P0C if c["role"] == "PRIMARY" and c["recomputed"] in hist_vals]
ok(not bad_primary, "khong dong PRIMARY nao mang gia tri strict lich su (2/5, 0/5): " + (", ".join(bad_primary) or "-"))

# Appendix D as rendered in the DOCX table (exact cells per row)
def docx_tables(xml):
    out = []
    for tb in re.findall(r"<w:tbl>.*?</w:tbl>", xml, re.S):
        rows = [[re.sub(r"<[^>]+>", "", c) for c in re.findall(r"<w:tc>.*?</w:tc>", tr, re.S)] for tr in re.findall(r"<w:tr[ >].*?</w:tr>", tb, re.S)]
        out.append(rows)
    return out
tabs = docx_tables(doc)
appD = next((t for t in tabs if t and t[0][:3] == ["ID", "Claim", "Vai trò"]), None)
ok(appD is not None, "Phu luc D: bang co cot 'Vai trò' trong DOCX")
if appD:
    byid = {r[0]: r for r in appD[1:]}
    ok(len(byid) == len(P0C), f"Phu luc D: {len(byid)} dong == {len(P0C)} claim trong claim_evidence_p0.csv")
    for cid, (val, role) in EXPECT.items():
        r = byid.get(cid, [""] * 6)
        ok(r[3] == val, f"Phu luc D {cid}: o 'Giá trị' = {r[3]!r} (mong doi {val!r})")
    for r in appD[1:]:
        if r[3] in hist_vals:
            ok(r[2].startswith("LỊCH SỬ"), f"Phu luc D {r[0]}: gia tri lich su {r[3]} duoc gan nhan LỊCH SỬ (thay {r[2]!r})")
    ok(not any("Độ nhạy: strict custom khi bỏ E4-T5c" in r[1] for r in appD), "Phu luc D: khong con cach dien dat cu '1/4 = do nhay'")
ok("claim_evidence_p0.csv" in flat, "Phu luc D trich nguon claim_evidence_p0.csv")

# E7-E9 definitions must match experiments/PLANNED_E7_E8_E9.md (canonical design) and stay PLANNED
plan = open("experiments/PLANNED_E7_E8_E9.md").read()
for eid, key in (("E7", "Tetragon"), ("E8", "Atomic Red Team"), ("E9", "unconfined")):
    ok(key in plan, f"{eid}: thiet ke goc chua '{key}'")
    row = next((r for t in tabs for r in t if r and r[0] == eid), None)
    ok(row is not None and key.split()[0] in " ".join(row) and "PLANNED" in " ".join(row),
       f"Bang thi nghiem {eid}: dinh nghia chua '{key}' va trang thai PLANNED ({row[1] if row else '-'})")

# Appendix C: current build script cited; historical runs labelled as such
appc = flat[flat.find("Phụ lục C"):flat.find("Phụ lục D")] if "Phụ lục D" in flat else ""
ok("build_report_p0.sh" in appc, "Phu luc C trich build_report_p0.sh (ban hien hanh)")
ok("Bản ghi lịch sử" in appc and "verify_pipeline_20261104.txt" in appc, "Phu luc C tach ban ghi lich su va kiem tra lai hien tai")
# DEV-T1r wording (H-07): proc.name was not captured; never present it as shown by the alert
ok("cho thấy proc.name" not in flat and "cho thấy `proc.name" not in flat, "khong dien dat proc.name nhu da bat truc tiep (H-07)")
ok(re.search(r"Nhánh proc\.name: INFERRED", flat) is not None, "nhanh proc.name ghi INFERRED")
# canonical repository string
ok("ANONYMOUS REPOSITORY URL: NOT AVAILABLE — PUBLICATION PENDING" in flat, "chuoi repository chuan co trong PDF")
ok(not re.search(r"anonymous\.4open\.science/r/|github\.com/(?!(?:falcosecurity|cilium|aquasecurity|opencontainers|redcanaryco)/)[A-Za-z0-9-]+", flat),
   "khong co URL repository nao (an danh hay khac) ngoai nguon tham khao")
# notation: khong dung dau phay thap phan (vd 0,14) va khong co tu ngu overclaim
ok(not re.search(r"\b\d+,\d+\s*(ms|s|%)", flat), "khong co dau phay thap phan truoc don vi")
for bad in ("overhead bằng 0", "không có overhead", "chứng minh tổng quát hóa", "đã chứng minh khả năng tổng quát"):
    hit = [m.start() for m in re.finditer(re.escape(bad), flat)]
    ctx = [flat[max(0, h - 40):h] for h in hit]
    neg = all(re.search(r"(không|chưa|Không|not)\s*(có nghĩa là|đủ để|được hiểu là|phải)?[^.]{0,40}$", x) for x in ctx)
    ok(not hit or neg, f"cum '{bad}' chi xuat hien trong ngu canh phu dinh")
print(f"\nKET QUA: {len(fails)} FAIL, {len(warns)} WARN, {pages} trang, {nfig} hinh, {ntab} bang")
sys.exit(1 if fails else 0)
