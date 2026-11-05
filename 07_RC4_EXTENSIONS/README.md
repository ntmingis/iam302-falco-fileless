# 07_RC4_EXTENSIONS — RC4 follow-up evidence (2026-11-04)

Sanitized subset of the RC4 hand-off package (`Group8_RC4_Handoff_v4`, private SHA-256 cb3a56ce…e0e493cc).
Pre-registered experiments, run with n = 5 per variant on the same VM as RC1–RC3 (Falco 0.45.0, falco-rules-5.2.0,
Docker 28.4.0 / runc 1.3.3, kernel 6.8). Results are reported in report §8.4, §8.6 and §9 and are never pooled with E4.

| Folder / file | Content |
|---|---|
| `prereg/` | pre-registrations and `PREREG_LEDGER.txt` (hashes recorded before each run) |
| `runs/` | run scripts used for P1, E6, E7, E8, E9 |
| `tools/` | parsers, scorers and independent recount scripts |
| `tables/` | result tables (summary + per-variant) |
| `raw_excerpts/` | verbatim Falco event lines for the P1 branch capture |
| `external_provenance/` | pinned sources of external variants (Atomic Red Team @ d0cc590b, event-generator v0.13.0) |
| `integrity/p1_scorer_audit.md` | defect found in P1 scorer v1 and its fix (v1 output kept as `*_DEFECTIVE.csv`) |
| `deviations.md`, `limitations_update.md` | deviations from pre-registration; RC4 limitations |
| `ai_log_rc4.md` | AI activity log of the RC4 phase (AL-29…AL-45) |

Known table issues (kept as recorded, corrected in the report): `tables/branch_matrix_rc4.csv` labels branch B2's
RC3 status as INFERRED, whereas RC3 had verified the non-match; `tables/r4_scenarios_rc4.csv` is an unscored
placeholder — use `tables/p1_summary_rc4.csv` for R4 results.

Redaction: host name → `lab-vm`, home path → `/home/labuser`, local logins → `labuser`. No measurement was changed.
