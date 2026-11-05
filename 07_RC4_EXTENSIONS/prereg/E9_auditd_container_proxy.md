# Pre-registration — E9: Auditd container proxy (AppArmor default vs unconfined)

Status at registration: **NOT TESTED** and gated on an owner VM snapshot.

## Hypothesis
`parse_e1.py`'s `audit_state` uses `subj=docker-default` as the container proxy. Under
`--security-opt apparmor=unconfined`, audit records carry `subj=unconfined`, so the current parser classifies every
container technique as host → Auditd `miss`, even though the telemetry is present. The size of this misclassification is
the quantity to measure.

## Pre-conditions
Owner confirms a VM snapshot first (`pre-RC4`). No `--privileged`, no host mounts, no added capabilities, benign
payloads only.

## Variants, configs and n
Variants T1, T3b, T4, T5, DEV-T1r. Two container configs: (a) default AppArmor (`docker-default`); (b)
`--security-opt apparmor=unconfined`. n = 5 each. Falco unaffected (container identified via the container plugin /
cgroup).

## Two scorings (pre-registered)
1. RC3 parser (`subj=docker-default` proxy) — unchanged, as the baseline.
2. A **new** parser file (e.g. `rc4/tools/parse_e9_altscope.py`) using an alternative scoping fixed in advance — the
   container's PID namespace or cgroup from a `/proc` mapping captured at run time. `parse_e1.py` is **not** edited.

## Decision rule
Report, per variant and config, Auditd `specific` vs `miss` under each scoring. The misclassification size =
(container techniques scored `miss` by proxy-1 while telemetry is present) under the unconfined config. If the
alternative scoping recovers them, that quantifies the proxy's weakness and motivates the parser change; report it as a
measured limitation of the RC3 proxy, not a detection change in Falco.
