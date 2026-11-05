# Reproduction instructions (RC3)

Paths are relative to this package unless prefixed "repo:". The scripts assume the original repository layout; this
package is a curated copy for review. **Export `LC_ALL=C`** in every shell before running the Python/awk tooling.

## 0. Verify this package first (no sudo)
```
sha256sum -c SHA256SUMS.txt                                   # inside this directory: every file except SHA256SUMS.txt
python3 06_REPRODUCIBILITY/scripts/build_release_candidate.py verify   # from the repo root: also copy == source
```
`verify` fails on a missing file, hash mismatch, untracked file, source drift, secret, or broken required reference.

## 1. Recompute the derived P0 tables (no sudo, offline)
```
bash repo:final_evidence_report/verification/verify_pipeline.sh <workdir>   # raw -> parser -> tables, compares byte-by-byte
python3 repo:report/tools/e4_reclassify.py       # E4 strict-unseen from raw: expect custom 1/4, default 0/4
python3 repo:report/tools/build_p0_claims.py     # Appendix D claim table with cross-checks: expect 33 claims, 0 mismatch
```
Recorded results: `06_REPRODUCIBILITY/verification/verify_pipeline_20261104.txt` (43 SAME, 1 DIFF-EXPECTED for E5 locale,
16/16 unit tests OK; the 7 DIFF lines are tables not produced by `build_tables.py`; the E3a journald step is not
reproducible any more because the 2026-10-21 journal has rotated) and the historical
`verify_pipeline_output_20261029.txt` (46 SAME, 1 DIFF-EXPECTED).

## 2. Validate rule syntax (no sudo)
```
falco -V 06_REPRODUCIBILITY/configs/rules/custom_rules.yaml        # expect 0 errors / 0 warnings
falco -V 06_REPRODUCIBILITY/configs/rules/candidate_rules_v2.yaml  # R4 candidate: syntax only
falco -V 03_P1_EVIDENCE/DEV_T1r/candidate_rules_copy/lab_diag_fields.yaml
```
Syntax validation does **not** demonstrate detection behaviour.

## 3. Re-run the P0 campaigns (owner, sudo — on the VM)
Privileged; prepared scripts in the repo (`campaign.sh`, `run_e1.sh`, `run_e5.sh`, `ruleset.sh`, `preflight.sh`) and the
sanitized `06_REPRODUCIBILITY/scripts/run_e2.sh` (`export E2_DB_PASSWORD=<throwaway>` first). Stop the falcoctl follower
before any Falco restart so rule hashes stay frozen.

## 4. P1 — DEV-T1r level-3 tests (owner, sudo — NOT YET RUN)
**NOT TESTED.** Commands, state capture/restore and rollback: `03_P1_EVIDENCE/branch_coverage/sudo_commands.md`.
Order: DIAG-FIELDS → NT-B1/B2/B4 → R4-A/B/D/E (matrix: `05_METHODOLOGY_AND_TRACEABILITY/experiment_test_matrix.yaml`).
After each run: `p1_evidence_collector.py --run-dir <run>`, `p1_validate.py`, `p1_report_generator.py --pdf`.
R4 scenario C is **not reproducible** on this VM.

## 5. Rebuild the report and AI audit (no sudo)
```
bash repo:report/build_report_p0.sh                                         # expect 19 pages, 0 FAIL / 0 WARN
PYTHONPATH=repo:report/.pylib python3 repo:tools/p1_report_generator.py --pdf   # Group 8 AI audit workbook + PDF
```
Do not overwrite the preserved earlier reports (`Final_Report*`).

## 6. Rebuild + rescan the anonymous package (no sudo, OFFLINE)
```
python3 repo:report/tools/make_anon_staging.py     # must end: zip_findings=0, RESULT PASS (0 findings)
python3 repo:tools/test_remediation_regressions.py # incl. checklist-hash and archive scans; expect all PASS
```
Then copy the new `sha256sum submission/anonymous_artifact.zip` into `submission/PUBLICATION_CHECKLIST.md`.
