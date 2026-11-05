# Environment (pinned)

_Carried over unchanged from RC1 (2026-11-03); unchanged because no experiment or sensor configuration changed during the 2026-11-04 remediation._

Captured from the canonical run `versions.txt` files and `03_P1_EVIDENCE/DEV_T1r/environment_metadata.txt`.
Single Ubuntu 22.04 VM; all privileged operations were run by the owner (the assistant had no sudo).

| Component | Version / value |
|---|---|
| Host kernel | `6.8.0-138-generic` (Ubuntu 22.04) |
| Falco | `0.45.0` (x86_64), modern eBPF (CO-RE) |
| Falco engine | `0.65.0` (version 65) |
| Falco driver | `11.0.0+driver` (api 11.0.0, schema 4.3.0) |
| Falco libs | `0.26.0`; plugin api `3.12.0` |
| Installed ruleset | `/etc/falco/falco_rules.yaml`, sha256 `30a1a60263ab97650c851011468da03b17fc0096a7cfa3b6686eba5de73b865b` (= falco-rules-5.2.0, byte-for-byte upstream main 2026-10-22) |
| `falco.yaml` sha256 | `ba9eb59a3bcea34078c6a514e515040aed80d9427f3a9b4292a93ef5ef8fdc09` |
| `falco_rules.local.yaml` sha256 | `25154e0f2012815109f953a95873e2895b2252f6cc8a8f3579edcbdbbacc26a3` |
| Docker | `28.4.0`, build d8eb465 |
| containerd | `containerd.io v1.7.28` (b98a3aace656…) |
| runc | `1.3.3` (spec 1.2.1); path `/usr/bin/runc` ∈ `lab_runc_paths` |
| rule matching | `first` (default) |
| falcoctl artifact-follow | `inactive` (follower stopped before any restart to freeze rule hashes) |

## Notes relevant to the evidence
- **runc memfd-clone was not observed** on this VM (0 `memfd_create` from containers across the
  500-container E2 churn). runc 1.3.3's default config does not self-clone here → **R4 scenario C
  is not reproducible** in this environment.
- The memfd exception under study is `known_memfd_execution_processes` (list item `runc`), from
  upstream rules PR #268 (commit `4633f29`), issue #3444.
- Falco alerts were read via `journalctl -u falco-modern-bpf -o cat`; `/var/log/falco/events.json`
  is `0600 root`. Audit logs are readable via the `adm` group.
- Locale: scripts export `LC_ALL=C` (the root sudo env uses a comma-decimal locale that breaks
  awk/printf floats in the CSVs).
