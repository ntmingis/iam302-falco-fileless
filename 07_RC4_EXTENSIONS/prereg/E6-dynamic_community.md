# Pre-registration — E6-dynamic: community rulesets loaded

Status at registration: **NOT TESTED** (owner runs privileged steps). E6 static prediction is VERIFIED as a prediction.

## Hypothesis
Loading the pinned community rulesets `falco-incubating-rules-6.0.1` and `falco-sandbox-rules-6.2.0` (with its 14
shipped-disabled rules enabled) alongside the default ruleset adds **no additional direct detection** for the lab's
fileless-execution variants, confirming the static analysis in `experiments/E6_community_ruleset/README.md` §3. It may
add misattributed alerts and false positives (drift rules on E2 workloads).

## Sources (pinned, sha256 recorded)
- `experiments/E6_community_ruleset/upstream/falco-incubating-rules-6.0.1.yaml`
  sha256 `47bf87041e2f39ca336e7acf1ae4e6183771a92e81031f367d01f2b49cabe1ac`
- `experiments/E6_community_ruleset/upstream/falco-sandbox-rules-6.2.0.yaml`
  sha256 `f05ad34f07c43930932ea6dd84c08a37bc8e5ba9f88901ca091ff1b52b3f33d3`
- Enable-all overlay (built and syntax-validated this phase, 0 err/0 warn):
  `rc4/rules/e6_enable_all_sandbox.yaml`. It sets `enabled: true` via `override: {enabled: replace}` on exactly the 14
  sandbox rules that ship disabled; it changes no condition. Verified with `falco -L`: sandbox enabled count 81 → 95.

The 14 enabled rules: Unexpected inbound connection source; Read Shell Configuration File; Interpreted procs inbound
network activity; Interpreted procs outbound network activity; Unexpected K8s NodePort Connection; Create Hidden Files
or Directories; Detect outbound connections to common miner pool ports; Container Drift Detected (chmod); Container
Drift Detected (open+create); Container Run as Root User; Java Process Class File Download; Modify Container Entrypoint;
Container Accessing GPU Device; GPU Management Tool Run in Container.

## Variants, rulesets and n
Two ruleset conditions: (1) default + incubating + sandbox + overlay; (2) default + incubating + sandbox + overlay + v1.
Run the E1 (11) + E4 (7) + DEV-T1r variants (`run_e1.sh` TECHS), n = 5, plus the E2 benign workloads (`run_e2.sh`) for
false-positive cost. Community rules loaded via a bounded temp Falco `-r` (Method A) where the concurrent instance is
available; if not, this is BLOCKED (Method B requires separate owner approval and is not part of this prereg).

## Direct-detection map (pre-registered, before results)
For E6, "direct" requires a community rule whose documented intent matches the technique family AND fires on the
expected container. The static analysis predicts **no** community rule is direct for any lab family (memfd, /dev/shm,
/proc/self/fd exec, interpreter, download-pipe, LD_PRELOAD, ptrace beyond the already-present stable rule). `parse_e1.py`
has no `community` DIRECT map; a `community` map must be added as a NEW parser variant and recorded here before scoring —
not edited into the existing default/custom map.

## Decision rule
Report, variant by variant, whether the static "no additional direct detection" prediction is **confirmed** or
**refuted**. Any community rule that fires is classified direct / misattrib / FP by the pre-registered map. FP cost on E2
is reported separately (Wilson interval on windows with ≥1 FP).
