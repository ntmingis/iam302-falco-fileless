# raw_excerpts — key raw lines backing the RC4 VERIFIED claims

These are verbatim raw lines (not summaries) from the append-only evidence, with SHA-256 of the full line incl. its
trailing newline. Full raw files live under `evidence/P1_DEV_T1r/raw_logs/`, `rc4/runs_out/` and the per-experiment
`rc4/tables/` (with the independent recounts in `rc4/tools/recount_*.py`).

## P1 branch decisions — `p1_branch_lines.jsonl` (run `rc4_p1_20261104T123454Z`)
| # | Source line | sha256 (full line) | What it proves |
|---|---|---|---|
| 1 | `diag_fields_raw.json:3` | `1214efacfb24b5c42202b1c30278f514d9f641f7eda1bdca584bd4630b5cb194` | DEV-T1r memfd execve: `proc.exepath=memfd:runc_cloned:/proc/self/exe`, `proc.is_exe_from_memfd=true` → **B3** captured |
| 2 | `branch_isolation_raw.json:4` | `3367b469b31b075c1497727d95e314520a2a853f3df39761316eceea47fbaac2` | NT-B4: `proc.exe=memfd:runc_cloned:/proc/self/exe` while `proc.exepath=memfd:not_runc_name` → **B4** argv0 bypass; default memfd rule 0/5 for this token |
| 3 | `branch_isolation_raw.json:7` | `9a94eecfe83d9c3c28f7e77a019ec3bff1cb019e40e560cab39ec0f74beb768e` | NT-B1: `proc.name=memfd:runc` (prefixed) → a bare `runc` list match is impossible; default fired 5/5 |

All three hashes re-verify against `rc4/integrity/p1_scorer_audit.md`.

## Other experiments — where the raw evidence is
- **R4 behaviour:** `evidence/P1_DEV_T1r/raw_logs/rc4_p1_20261104T123454Z/r4_scenarios_raw.json`; per-token
  classification in `rc4/tables/p1_per_token_rc4.csv` (R4A r4=5/5, R4B default=5/5, R4D/E both 0).
- **E6-dynamic:** `rc4/runs_out/` (foreground-falco capture) → `rc4/tables/e6_*` (0/19 direct; 945/969 other alerts).
- **E8:** `rc4/runs_out/e8_*` → `rc4/tables/e8_variant_summary_rc4.csv` (default 1/8, v1 5/8).
- **E9:** `rc4/runs_out/…e9…` + audit windows → `rc4/tables/e9_summary_rc4.csv` (0/25 proxy vs 25/25 lineage).
- **E7:** `rc4/runs_out/e7_tetragon_…`, `rc4/runs_out/e7_tracee_20261104T145244Z/tracee_rx.log` →
  `rc4/tables/e7_*_summary.csv` (Tetragon 0/4 covered, Tracee 7/9 covered).

Each run dir carries its own `SHA256SUMS.txt` / `manifest.txt`. Nothing here was edited; excerpts are byte copies.
