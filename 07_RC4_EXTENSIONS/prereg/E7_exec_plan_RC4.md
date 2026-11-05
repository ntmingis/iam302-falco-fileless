# E7 — execution-plan supplement (registered 2026-11-04T12:57:38Z, BEFORE any E7 run; no E7 data seen)
Supplements `E7_second_sensor.md` (unchanged).
- Deviation: same VM (no second VM); protection = per-tool restore point + VMware snapshot pre-RC4 + one sensor at a time,
  Falco service stopped during each sensor run.
- Tetragon pinned v1.7.1 (2026-08-25; latest v1.8.0 is 5 days old, not chosen). Tracee pinned v0.23.2: v0.24.1 was
  fetched first but is BLOCKED here (dynamic binary needs GLIBC_2.38, Ubuntu 22.04 has 2.35; the static build cannot load
  signatures; the official container needs --privileged, which is forbidden). URLs + sha256 in rc4/external/*/FETCH_LOG.tsv.
- "Install" = run from the extracted, checksum-verified release dir in the foreground (no files copied to /usr/local,
  /etc or systemd); "uninstall" = stop + remove runtime residues (/sys/fs/bpf/tetragon, /var/run/tetragon, /tmp/tracee)
  and verify absence. No TracingPolicy loaded for Tetragon (base sensor only).
- Harness run_e1.sh unchanged, E1 11 + E4 7 + DEV-T1r, REPS=5. Runner rc4/runs/e7_run.sh. Scorer rc4/tools/parse_e7.py
  (direct maps fixed in its docstring; T7 not comparable for Tracee; uncovered families labelled no-model).
