# Pre-registration — E8: independent external variants

Status at registration: **NOT TESTED** (owner runs privileged steps; sources not yet fetched).

## Hypothesis
Rule v1 (and R4/v2) detect fileless-execution variants that were **not designed by the rule author**. Because v1's E4
"unseen" set is author-held-out but still lab-authored, E8 is the first set independent of the rule author. Detection
rates on E8 may differ from E4 and must be reported separately.

## Rule freeze (MUST precede source selection)
Before any variant is selected or fetched, hash v1 and v2 into the ledger:
- `rules/custom_rules.yaml` v1 sha256 `8811248cb839ee69494cb43d5331288b72c67341a89ee2f71c15b7abaeb9ed21`
- `rules/candidate_rules_v2.yaml` v2 sha256 `5cfcfa9df85389fd22acb7018bc19eb0696d95bb3cc9c480ba3e669c98ef5881`
No rule may be edited after seeing E8 results; any later change becomes `custom_rules.v3.posthoc.yaml`, labelled
POST-HOC and never counted as an E8 detection.

## Sources (fetch OUTSIDE the lab network; record URL + commit + sha256 before copying in)
- Atomic Red Team `redcanaryco/atomic-red-team` @ `d0cc590b` — Linux tests for T1059.004, T1059.006, T1574.006.
- `falcosecurity/event-generator` — only syscall actions for fileless exec, memfd, `/proc/self/fd`, interpreters,
  pipe-to-shell, LD_PRELOAD.
Downloaded archives are untrusted: each into its own empty directory, scripts read with `python3 -I`, paths passed as
arguments, nothing executed from the download directory. Then mirror the needed payload onto `falco-lab-server` (internal
network); no outbound network from the lab network during measurement.

## Selection rule (pre-registered)
Include every Linux atomic in those techniques that runs **unprivileged** inside `falco-lab-target` on the internal
network. Exclude anything that persists, alters the host, needs outbound network, deletes data outside `/tmp`, or needs
host root. List each included/excluded test with its reason. A payload made benign is recorded as an ADAPTED variant with
the exact diff. `/etc/ld.so.preload` variants run only in a disposable container, never on the host.

## Scoring
Score default, v1, and default + v1 + v2, each n = 5. Unit = variant. Wilson 95% on variants; for k = 0 also the
one-sided 95% Clopper–Pearson upper bound. Record `class=independent_external` in `report/tables/test_independence.csv`.

## Decision rule
Report E8 k/n with intervals **separately** from E4. Do not merge E8 into the E4 "unseen" claim. A detection on E8 is
the first evidence of generality; absence of detection narrows the generality claim.
