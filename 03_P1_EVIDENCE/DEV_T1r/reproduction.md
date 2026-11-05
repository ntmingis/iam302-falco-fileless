# Reproduction — P1 DEV-T1r evidence set

Two no-sudo levels reproduce the **existing** finding and the field-semantics proof from shipped raw data; level 3 is the owner's privileged run.

## Level 1-2 (no sudo) — reproduce from shipped data
```bash
cd /home/labuser/lab/falco_lab_containers

# (a) DEV-T1r states from raw Falco events (default miss 5/5, custom 5/5)
python3 report/tools/e4_reclassify.py                                   # DEV rows

# (b) exception-relevant fields captured in the DEV run
python3 evidence/dev_t1r_branch_coverage/extract_dev_fields.py

# (c) proc.exe=argv0 proof from the benign memfd probe (the field-semantics evidence)
python3 -I -c "import json
for l in open('results/e1_probe_20261020_235831_probe/falco_events.json'):
    import json as _j
    try: e=_j.loads(l)
    except Exception: continue
    o=e.get('output_fields',{}) or {}
    if e.get('rule')=='LAB Probe exec fields' and o.get('proc.is_exe_from_memfd') in (True,'true'):
        print({k:o.get(k) for k in ('proc.name','proc.exe','proc.exepath','proc.is_exe_from_memfd')}); break"

# (d) R4 + v1 syntax validation on the installed Falco (no sudo)
falco -V /etc/falco/falco_rules.yaml -V rules/custom_rules.yaml -V rules/candidate_rules_v2.yaml
```
Expected (c): `{'proc.name':'memfd:falco_ben','proc.exe':'falco_memfd_py','proc.exepath':'memfd:falco_benign_memfd','proc.is_exe_from_memfd':True}`.

## Level 3 (sudo, owner) — new tests
Follow `evidence/dev_t1r_branch_coverage/sudo_commands.md`. Put the produced raw logs in `raw_logs/`, recompute `SHA256SUMS.txt`, write `docs/dev_t1r_level3_results.md`.

## Integrity
Verify this evidence set: `cd evidence/P1_DEV_T1r && sha256sum -c SHA256SUMS.txt` (covers everything except `raw_logs/`, which fills after level 3). Hashes in the docs refer to the original unmodified raw files under `results/` (read-only; never rewritten).
