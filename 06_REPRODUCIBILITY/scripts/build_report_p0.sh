#!/usr/bin/env bash
# build_report_p0.sh - dung report/FINAL_REPORT_P0_REVISED.docx + .pdf (ban P0, 2026-11-03).
#   bash report/build_report_p0.sh
# KHONG ghi de ban goc / ban revised. Khong can sudo, khong chay lai thi nghiem, chi doc results/.
# Can: python3 + matplotlib + PyYAML, LibreOffice (soffice), poppler-utils.
set -euo pipefail
export LC_ALL=C.UTF-8
cd "$(dirname "$0")/.."
for c in python3 soffice pdfinfo pdffonts pdftotext pdfimages pdftoppm; do
  command -v "$c" >/dev/null || { echo "thieu lenh: $c"; exit 1; }; done

echo "[1/6] bang dan xuat + claim->evidence";  python3 report/tools/build_revised_tables.py
echo "[2/6] E4 phan loai lai (tu raw log)";    python3 report/tools/e4_reclassify.py >/dev/null
echo "[2b/6] claim->evidence ban P0";          python3 report/tools/build_p0_claims.py
echo "[3/6] consistency audit CSV";            python3 report/tools/build_consistency_audit.py >/dev/null
echo "[4/6] DOCX";                             python3 report/tools/make_report_p0.py
echo "[5/6] PDF (LibreOffice headless)"
prof=$(mktemp -d); trap 'rm -rf "${prof:?}"' EXIT
timeout 300 soffice -env:UserInstallation="file://$prof" --headless --convert-to pdf \
  --outdir report report/FINAL_REPORT_P0_REVISED.docx >/dev/null 2>&1
[ -s report/FINAL_REPORT_P0_REVISED.pdf ] && [ report/FINAL_REPORT_P0_REVISED.pdf -nt report/FINAL_REPORT_P0_REVISED.docx ] || { echo "xuat PDF that bai"; exit 1; }
echo "[6/6] kiem tra (check_report_p0.py)"
python3 report/tools/check_report_p0.py > report/evidence/check_report_p0.txt || { grep -E '^(FAIL|WARN)' report/evidence/check_report_p0.txt; tail -1 report/evidence/check_report_p0.txt; exit 1; }
tail -1 report/evidence/check_report_p0.txt
sha256sum report/FINAL_REPORT_P0_REVISED.docx report/FINAL_REPORT_P0_REVISED.pdf > report/evidence/report_p0_sha256.txt
echo "XONG: report/FINAL_REPORT_P0_REVISED.{docx,pdf}"
