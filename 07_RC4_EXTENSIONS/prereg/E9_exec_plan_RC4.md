# E9 — execution-plan supplement (registered 2026-11-04T12:47:14Z, BEFORE any E9 run; no E9 data seen)

Supplements `E9_auditd_container_proxy.md` (unchanged).
- Runner `rc4/runs/e9_run.sh`; variants memfd(T1) procfd_nolink(T3b) python(T4) curl(T5) dev_memfd_runcname(DEV-T1r); REPS=5.
- Config (a): ./run_e1.sh unchanged (labctl.sh -> AppArmor docker-default).
- Config (b): rc4/e9_harness/run_e1.sh = byte-identical copy of run_e1.sh; its ./labctl.sh is a variant whose ONLY change
  is `--security-opt apparmor=unconfined` on falco-lab-target and falco-lab-client (no --privileged, no host mounts, no
  cap-add; network falco-lab Internal=true). Payloads = the existing run_* functions, unchanged.
- Falco: installed falco-modern-bpf, default ruleset 30a1a602…; scored by parse_e1.py unchanged (side result).
- Auditd scoring 1 (RC3 proxy): parse_e1.py unchanged.
- Auditd scoring 2 (ALT, NEW parser rc4/tools/parse_e9_altscope.py): container membership = audit pid->ppid lineage reaches
  the init or containerd-shim PID of a running falco-lab-* container captured from /proc at run time by
  rc4/runs/e9_proc_sampler.sh (pidns inode + cgroup logged for reference). All other matching identical to parse_e1.
- Primary quantity: misclassification = # payload-ok windows (per variant, unconfined) with auditd_rc3=miss AND auditd_alt=specific.
- Sanity: under config (a) both scorings are expected to agree (any disagreement is reported, not tuned away).
