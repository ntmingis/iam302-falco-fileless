# raw_logs/ — placeholder for level-3 privileged-run output

**Empty by design.** New raw Falco/Auditd logs from the privileged tests go here **after** the owner runs `evidence/dev_t1r_branch_coverage/sudo_commands.md`. Nothing has been run yet; all level-3 tests are **NOT TESTED**.

Expected files once the owner runs the tests (names used by the sudo_commands):
- `diag_fields_raw.txt`        — DIAG-FIELDS PROBE line(s) for the live DEV-T1r memfd execve
- `branch_isolation_raw.txt`   — NT-B1 / NT-B2 / NT-B4 alerts + recorded fields
- `r4_scenarios_raw.txt`       — R4-A/B/D/E alerts
- `falco_start.txt`, `validate.txt` — sensor start log and `falco -V` output for the loaded stack

After adding files here: recompute `../SHA256SUMS.txt`, then record outcomes in `docs/dev_t1r_level3_results.md` and flip the NOT TESTED rows in `docs/r4_mitigation_evaluation.md` and `docs/dev_t1r_branch_coverage.md`.

Do **not** place anything from E1–E5 here; this directory is only for the new P1 level-3 run.
