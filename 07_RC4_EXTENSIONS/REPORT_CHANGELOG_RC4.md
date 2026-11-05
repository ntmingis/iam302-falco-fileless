# REPORT_CHANGELOG_RC4.md — what changed from Final_Report_Revised → FINAL_REPORT_RC4

Source doc: `rc4/report_input/FINAL_REPORT_REVISED.docx` (sha256 `d320c36b…`, owner-copied read-only).
Output: `report/FINAL_REPORT_RC4.docx` + `.pdf` (25 pages). Generator `rc4/tools/update_report_rc4.py` (python-docx);
validator `rc4/tools/check_report_rc4.py` → **0 FAIL, 0 WARN**. Numbers are read from `rc4/tables/*.csv` and
`rc4/test_status.json`, not typed by hand.

**Scope rule honoured:** only the sections below were edited. **E4 and E8 are never merged**; the historical **2/5** is
kept only as a labelled sensitivity/`lịch sử` row; the E4 strict-unseen result (custom 1/4) is unchanged.

| Section (para/table index) | Change | Measured value inserted |
|---|---|---|
| Cover / change summary (para 8) | Added an RC4 change-summary paragraph noting the execution phase, n=5, Wilson intervals, and that RC3 is unchanged | — |
| Abstract (para 11) + Vietnamese abstract (para 14) | Added RC4 headline: B4 bypass VERIFIED, R4 PARTIAL, community rules 0/19, E9 AppArmor dependence, Tracee 7/9 | k/n as below |
| Bảng 2 (branch table, T1 cells) | B1/B4 status updated to VERIFIED (captured); B2 INCONCLUSIVE; B3 unchanged | B4 default 0/5; B1 default 5/5 |
| §8.4 (para 104) | DEV-T1r branch coverage: all 4 fields captured at the memfd execve; argv0 (B4) bypass added | `name=memfd:runc_clon exe=x exepath=memfd:runc_cloned:/proc/self/exe pname=containerd-shim` |
| §8.6 (para 113) + Bảng 13 (T12) | R4 behaviour A/B/D/E measured; overall PARTIAL; C NOT REPRODUCIBLE | R4-A 5/5 TP; B/D/E 0/5 |
| §9 (paras 119–123) | New E6/E8/E9/E7 results subsections | E6 0/19; E8 1/8 & 5/8; E9 0/25 vs 25/25; E7 Tetragon 0/4, Tracee 7/9 |
| §10 (para 125) | Discussion: two attacker-settable bypasses; AppArmor dependence; community rules add noise not coverage | — |
| §11 (para 130) | Limitations: n=5, single VM/runtime, R4-C not reproducible, Tetragon base-only | Wilson intervals cited |
| §13 (para 145) | Conclusion updated with RC4 findings | — |
| Appendix C (T17) | Added RC4 run ids + integrity proof (RC3 149/149, PRE_RC4 1895/1895 unchanged) | run `rc4_p1_20261104T123454Z` etc. |
| Appendix D (T18, claims C37→C51) | New RC4 claim→evidence rows from `claim_evidence_p0.csv` build + RC4 claims | RC4-1…RC4-11 |

## Measured values referenced (from `rc4/tables/`)
- P1 / branches (`p1_summary_rc4.csv`): DIAG default 0/5; NT-B1 5/5; NT-B2 5/5; NT-B4 0/5; R4-A r4=5/5, R4-B default
  5/5, R4-D/E both 0/5.
- E6 (`e6_summary_rc4.csv`): community_direct 0/19 both conditions, Wilson [0.00,0.17], CP upper 0.15; 945 / 969 other
  alerts.
- E8 (`e8_variant_summary_rc4.csv`): default 1/8 [0.02,0.47]; v1 5/8 [0.31,0.86]; default+v1+v2 5/8 [0.31,0.86].
- E9 (`e9_summary_rc4.csv`): unconfined proxy 0/25 [0.00,0.13] (CP upper 0.11) vs lineage 25/25 [0.87,1.00]; 25 recovered.
- E7 (`e7_*_summary.csv`): Tetragon v1.7.1 covered 0/4 (no-model=15); Tracee v0.23.2 covered 7/9.

## Statuses preserved exactly (not changed to pass a check)
- B2 stays **INCONCLUSIVE**; R4 overall stays **PARTIAL**; R4-C **NOT REPRODUCIBLE**; Tracee v0.24.1 **BLOCKED**.
- The two `check_report_rc4.py` fixes this build were to the **checker's detection logic** (historical-marker regex and
  login-name word boundary), after a diagnostic confirmed the report text was already correct — **no report number,
  label or status was altered to make a check pass.**

## Preserved earlier reports (not overwritten)
`report/FINAL_REPORT_P0_REVISED.{docx,pdf}`, `report/Final_Report_Revised.{docx,pdf}`, `report/Final_Report.{docx,pdf}`.
