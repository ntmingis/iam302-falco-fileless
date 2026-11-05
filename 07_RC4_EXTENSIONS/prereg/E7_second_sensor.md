# Pre-registration — E7: second sensor (Tetragon / Tracee)

Status at registration: **NOT TESTED** — lowest priority; requires a separate VM or snapshot revert. Design from
`experiments/PLANNED_E7_E8_E9.md` §E7.

## Hypothesis
A second runtime sensor may detect some lab fileless variants that Falco's default/custom rules miss, or may miss some
Falco catches. Event-model differences (not detection gaps) must be stated before comparison.

## Protocol (pre-registered)
- Separate VM, same Ubuntu 22.04 / kernel 6.8 / Docker 28.4.0 / runc 1.3.3; snapshot before each tool.
- One sensor at a time (Falco, then Tetragon, then Tracee); never two on the same measurement run. Auditd stays as the
  control. Pin each tool's version and policy/signature hash.
- Same harness (E1 + E4 + DEV-T1r), n = 5, same internal network.
- Per tool, pre-register which event/signature counts as `direct` for each variant:
  Tetragon `binary_properties` / "Fileless Execution" policy; Tracee TRC-105, TRC-107, TRC-103, TRC-1022.
- Note any variant where the tool's model makes it not comparable (e.g. lab T7 attach/detach vs Tracee TRC-103
  POKETEXT/POKEDATA — a definition difference, not a miss).
- Restore the RC3 configuration afterwards and prove its hashes.

## Decision rule
Report per-tool, per-variant direct/miss with the pre-registered map, and label model-level incomparabilities
explicitly as INFERRED differences, never as detection results.
