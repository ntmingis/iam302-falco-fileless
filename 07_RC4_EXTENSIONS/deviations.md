# Deviations from pre-registration (RC4 phase, 2026-11-04)

1. **Measurement phase not entered.** The pre-registrations assume a privileged run. The assistant has no sudo and the
   project rule forbids it using sudo, so no experiment ran. Every experiment stops at pre-registration + owner handoff.
   This is the governing deviation; all others below follow from it.
2. **No VM snapshot taken by the assistant.** `00_snapshot_and_preflight.sh` asks the owner to take `pre-RC4`; until the
   owner confirms it, E9/E7 must not run. Recorded, not resolved.
3. **E6-dynamic capture path undecided.** The prereg assumed Method A (bounded temp Falco). The RC3 harness reads the
   installed sensor's JSON, so Method A needs a new capture wrapper, or Method B (an approved /etc/falco change). Neither
   was done; E6-dynamic is BLOCKED. No `community` DIRECT map was added to any parser yet (correctly deferred so it is
   fixed before results, not after).
4. **E8 sources not fetched.** Deferred to the owner (fetch outside the lab network, record URL+commit+sha256). v1/v2
   were frozen in the ledger first, so this deviation does not compromise independence.
5. **No post-run environment capture.** `environment/environment_post.txt` equals the pre-capture by construction
   because the host was not changed; the owner must recapture it after real runs and the restore step.

## Prompt-2 pass
6. **Part A not performed → whole autonomous run blocked at B0.** `sudo -n` asks for a password; no installed scripts,
   markers, or report input exist. Per fail-closed rules nothing privileged was attempted and the report was not edited.
   The six step scripts were prepared (B1) so Part A can proceed; four are NEEDS-OWNER-REVIEW stubs and must be finished
   and reinstalled by the owner before Prompt 2 can execute any experiment.

## Prompt-4 pass (ACTUAL execution; owner granted 24h passwordless sudo 2026-11-04T19:29+07)
The governing deviation (1) is LIFTED for this pass: the owner granted time-limited sudo and confirmed the override of
the CLAUDE.md no-sudo rule (ledger 2026-11-04T12:35Z). Snapshot pre-RC4 (2), report input, and the autonomy record were
provided by the owner. Experiments were executed. New deviations this pass:

D-P1-1. Runbook used `falco --modern-bpf`; Falco 0.45 rejects that flag ("Option 'modern-bpf' does not exist"). Replaced
  with `-o engine.kind=modern_ebpf` (the same engine the installed service uses). Attempt-1 raw dir kept; no payload ran
  in it. All start/smoke checks made fail-closed on non-zero exit.
D-P1-2. `score_p1.py` v1 read the DIAG rule's events for the docker-exec python3 parent and the NT variants too, so it
  reported field values of the wrong process. Fixed v2 to take fields only from the DEV-T1r memfd execve
  (is_exe_from_memfd=true) in diag_fields_raw.json. v1 output preserved as branch_matrix_rc4_scorerv1_DEFECTIVE.csv.
  Per-token scorer score_p1_tokens.py added (attribution by token substring) and registered before the run.
D-RP-1. Restore template fixed: auditd is reloaded with augenrules (never systemctl-restarted via the blanket loop);
  falco-modern-bpf restarted only if /etc/falco changed or it is inactive. docker restarted only if /etc/docker changed.
D-E6-1. Capture path RESOLVED by stopping falco-modern-bpf and running ONE foreground falco with the same falco.yaml so
  alerts still land in /var/log/falco/events.json; the RC3 harness (run_e1.sh/run_e2.sh) is driven UNCHANGED. Method B
  (/etc/falco change) was NOT used. rule_matching=all. New parser rc4/tools/parse_e6.py (community DIRECT map fixed
  before the run). E6 BLOCKED status is lifted.
D-E7-1. Same VM, not a second VM (per-tool restore point + snapshot + one-sensor-at-a-time instead). Sensors run from
  their extracted release dirs in the foreground; nothing installed to /usr/local, /etc or systemd.
D-E7-2. Tracee pinned v0.23.2, not latest v0.24.1: v0.24.1's dynamic binary needs GLIBC_2.38 (Ubuntu 22.04 has 2.35) and
  its static build cannot load signatures. Tetragon pinned v1.7.1 (v1.8.0 was 5 days old).
D-E8-1. curl atomics run in falco-lab-client (curl absent in target); ld.so.preload atomic in a disposable container
  (as the prereg required). ART download tests mirrored from a disposable in-network container (no outbound during
  measurement). 3 atomics BLOCKED (busybox/cpan/ping absent). Selection written before any run.
D-E9-1. Unconfined config uses a byte-identical copy of run_e1.sh with a labctl.sh variant whose only change is
  --security-opt apparmor=unconfined on target/client (no --privileged/mounts/caps). New parser parse_e9_altscope.py.
