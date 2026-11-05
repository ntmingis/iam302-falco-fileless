# E8 — execution-plan supplement (registered 2026-11-04T12:51:53Z, BEFORE any E8 run; no E8 data seen)
Supplements `E8_independent_variants.md` (unchanged). Rules frozen (ledger 10:44:34Z, re-affirmed 12:47:21Z).
- Sources fetched (URL, commit, sha256): rc4/external/art_d0cc590b/FETCH_LOG.tsv, rc4/external/event-generator_v0.13.0/FETCH_LOG.tsv.
- Selection: rc4/tables/e8_selection.csv (28 rows; 15 included; 9 primary fileless-family; 3 BLOCKED by missing tools).
- Deviation from prereg text "inside falco-lab-target": curl-based atomics run in falco-lab-client (curl absent in target);
  /etc/ld.so.preload atomic runs in a disposable container falco-lab-e8-ldso (as the prereg requires). Mirror for ART
  helper scripts: disposable container falco-lab-e8mirror (python http.server) on falco-lab (Internal=true).
- Conditions (foreground falco, service stopped, rule_matching=all): "default" = falco_rules.yaml + local;
  "v1" = default + rules/custom_rules.yaml (v1 cannot load without the default macros, as RC3 'custom');
  "defv1v2" = default + v1 + rules/candidate_rules_v2.yaml. REPS=5.
- Runner rc4/runs/e8_run.sh; scorer rc4/tools/parse_e8.py (direct map + variant rule in its docstring).
- Report as class=independent_external, separate from E4; never merged.
