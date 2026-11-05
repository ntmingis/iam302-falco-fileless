# E6-dynamic — execution-plan supplement (registered 2026-11-04T12:44:55Z, BEFORE any E6 run; no E6 data seen)

Supplements `E6-dynamic_community.md` (unchanged). Fixes how the run is done now that sudo is granted.

- Capture: falco-modern-bpf service STOPPED; ONE foreground `falco -o engine.kind=modern_ebpf -o rule_matching=all -r ...`
  using the installed /etc/falco/falco.yaml + config.d, so alerts land in /var/log/falco/events.json exactly where the
  UNCHANGED run_e1.sh / run_e2.sh read them. Runner: `rc4/runs/fg_falco_harness.sh`.
- rule_matching=all so that a stable rule matching first cannot mask a community rule (deviation from RC3 'first',
  chosen for this question only).
- Condition c1 "e6comm": falco_rules.yaml (pinned default 30a1a602…) + falco_rules.local.yaml (empty) + incubating-6.0.1
  + sandbox-6.2.0 + e6_enable_all_sandbox.yaml.
- Condition c2 "e6commv1": c1 + rules/custom_rules.yaml (v1, frozen 8811248c…).
- Workload: run_e1.sh REPS=5 over 19 techniques (E1 11 + E4 7 + DEV-T1r); run_e2.sh ROUNDS=10 CHURN=50 (RC3 params).
- Scoring: (a) parse_e1.py / parse_e2.py UNCHANGED. For c2 the base map must be the custom map, so parse_e1.py is run on a
  shadow directory (symlinks to the raw files + a versions.txt copy whose ruleset= line says custom); documented, raw
  untouched. (b) NEW parser variant rc4/tools/parse_e6.py with the community DIRECT map fixed in its docstring:
  download family (curl, e4_curl_script, e4_curl_sh) -> "Launch Ingress Remote File Copy Tools in Container"; all other
  techniques -> no community direct rule.
- Per-variant decision: static prediction "no additional direct detection" CONFIRMED iff community_direct = 0/5 on
  payload-ok windows; REFUTED otherwise. Wilson 95 % on variants; k=0 also one-sided Clopper–Pearson upper bound.
- E2 FP cost: parse_e2.py FP windows (Wilson) + count of community-rule alerts in E2 windows.
