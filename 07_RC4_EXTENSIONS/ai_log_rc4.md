# AI usage — RC4 phase (facts only), 2026-11-04

Group-level (Group 8) declaration, continuing `docs/ai_usage_declaration.md`. This phase was performed by Claude Code
(Anthropic, model Opus). No ChatGPT use is recorded for this phase. The phase ran in two passes on the same day: a
read-only **preparation** pass (no sudo) and, after the owner granted a time-limited 24h sudo exception
(2026-11-04T19:29+07; revoke timer 2026-11-05 19:29:40 +07), an **execution** pass that ran all six experiments.

**One-sentence summary for the report (group-level):** In the RC4 phase, Claude Code (Anthropic) prepared the
pre-registered test plans and scoring tools and then, under a time-limited owner-granted sudo exception, executed the
six experiments (P1 branch/mitigation, E6 community rulesets, E8 independent external variants, E9 AppArmor, E7 second
sensors), while the human owner granted and later revoked privilege and made every publication decision.

## Preparation pass (read-only; no sudo, no services changed)
- AL-29: Read the RC3 state, the P1 DEV-T1r runbook and expected-results, the E6 static analysis, and the harness
  (`run_e1.sh`, `run_e2.sh`, `ruleset.sh`, `parse_e1.py`, `parse_e2.py`, `labctl.sh`).
- AL-30: Took the preservation baseline (`PRE_RC4_SHA256.txt`, 1895 files) and the non-privileged environment capture.
- AL-31: Re-ran the existing read-only checks (unit tests; `verify_pipeline.sh`).
- AL-32: Built and syntax-validated `rc4/rules/e6_enable_all_sandbox.yaml` (0 err/0 warn; `falco -L` enabled 81 → 95).
- AL-33: Wrote the pre-registration files and hashed them (plus the config overlay and the v1/v2 rule freeze) into the
  ledger **before** any run.
- AL-34: Wrote the fail-closed P1 scorer and its tests.

## Execution pass (owner-granted 24h sudo; Method A; raw append-only; RC3 restored + re-verified after each run)
- AL-38: Recorded the RC4 sudo exception in CLAUDE.md and `rc4/owner_confirmations/`; mounted the shared folder
  read-only and **copied** (not moved) the report input, recording its source path + sha256.
- AL-39: Ran **P1** (`rc4_p1_20261104T123454Z`, n=5): DIAG-FIELDS captured all 4 branch fields at the memfd execve;
  NT-B1 control (default 5/5), NT-B4 argv0 bypass (default 0/5), NT-B2 non-match re-confirmed; R4 A (TP 5/5), B/D/E
  silent. Replaced the defective scorer v1 with a fail-closed v2 (identity selection of the memfd execve); audit in
  `rc4/integrity/p1_scorer_audit.md`, unit test PASS.
- AL-40: Ran **E6-dynamic** (foreground Falco, RC3 harness unchanged): community rulesets added 0/19 direct detection,
  with heavy misattribution/FP noise; custom v1 rules still fired.
- AL-41: Ran **E9** (AppArmor default vs unconfined): RC3 `subj=docker-default` proxy recall 0/25 under unconfined;
  PID/cgroup-lineage parser 25/25. Independent hex-decoding recount matched the scorer.
- AL-42: Ran **E8** on independently-sourced variants (ART @ d0cc590b, event-generator v0.13.0; pinned, sha256-logged
  in `FETCH_LOG.tsv`; fetched **outside** the falco-lab network): default 1/8, v1 5/8, default+v1+v2 5/8. E8 rules were
  frozen before data; kept strictly separate from E4.
- AL-43: Ran **E7** sequentially, one sensor at a time (Tetragon v1.7.1 base 0/4 covered — model difference, needs a
  TracingPolicy; Tracee v0.23.2 7/9 covered; ptrace NOT COMPARABLE; Tracee v0.24.1 BLOCKED on glibc). Sensors run from
  verified release dirs; residue removed; falco-lab `Internal=true` throughout.
- AL-44: Before each experiment created a restore point (config tar, service states, container digests, ruleset
  hashes, generated restore.sh); after each, restored and re-verified RC3 149/149 + PRE_RC4 1895/1895 unchanged.
- AL-45: Built `report/FINAL_REPORT_RC4.{docx,pdf}` with `update_report_rc4.py` (python-docx) and validated it with
  `check_report_rc4.py` to 0 FAIL. Wrote the responsible-disclosure **draft** (NOT sent) and the owner publication
  steps. Published and pushed nothing.

## Human decisions (owner / members)
- The owner granted the sudo exception, ran no experiment on the assistant's behalf beyond that grant, and will revoke
  privilege at cleanup. The owner decides whether to create any repository, whether/when to send the disclosure draft,
  and all publication. Per-member AI-usage confirmations are the members' own and were not touched by the assistant.

## Boundaries honoured
No account connected; nothing published, pushed or uploaded; falco-lab stayed `Internal=true`; no `--privileged`
containers and no host mounts into lab containers; no new attacker/payload code authored (only existing owner-reviewed
runbook commands and the pinned external generators were executed, each reviewed for side effects); raw evidence,
RC1/RC2/RC3 and backups unchanged (hash-proven).
