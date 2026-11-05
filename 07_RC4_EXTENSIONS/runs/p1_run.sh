#!/usr/bin/env bash
# p1_run.sh — RC4 P1-A + P1-B. Executes evidence/dev_t1r_branch_coverage/sudo_commands.md §A/§B/§C/§D (Method A)
# with the runbook's payload commands verbatim, repeated n=5 (prereg P1-A/P1-B). Only additions: loop, token
# suffix _r<i>, token logging (r4_toks.txt), a 1 s gap between payloads, and a per-run raw dir. Run as root.
set -u
export LC_ALL=C
cd /home/labuser/lab/falco_lab_containers
N=${N:-5}
RUNID=rc4_p1_$(date -u +%Y%m%dT%H%M%SZ)
RAW=evidence/P1_DEV_T1r/raw_logs/$RUNID; mkdir -p "$RAW"
DIAG=evidence/P1_DEV_T1r/candidate_rules_copy/lab_diag_fields.yaml
echo "RUNID=$RUNID"
DRV='device.?busy|permission denied|unable to (load|open)|failed to (open|attach)'
# ---- A
{ echo "falcoctl-artifact-follow=$(systemctl is-active falcoctl-artifact-follow)"
  echo "falco-modern-bpf=$(systemctl is-active falco-modern-bpf)"; echo "recorded_at=$(date -Is)"; } > "$RAW/service_state_before.txt"
falco --version > "$RAW/falco_version.txt" 2>&1
{ readlink -f "$(which runc)"; runc --version | head -1; } > "$RAW/runc_version.txt"
sha256sum /etc/falco/falco_rules.yaml > "$RAW/ruleset_hash_before.txt"
falco -V /etc/falco/falco_rules.yaml -V "$DIAG" -V rules/custom_rules.yaml -V rules/candidate_rules_v2.yaml > "$RAW/validate.txt" 2>&1
./labctl.sh up > "$RAW/labctl_up.txt" 2>&1
docker exec falco-lab-target test -x /usr/local/bin/python3 && echo "python3 present" > "$RAW/a4.txt" || echo "python3 MISSING" > "$RAW/a4.txt"
auditctl -l | grep -Ew 'execve|execveat' > "$RAW/auditd_execve_rules.txt"
falco -o engine.kind=modern_ebpf -M 3 -o json_output=true -o stdout_output.enabled=true -o log_level=info \
  -r /etc/falco/falco_rules.yaml >"$RAW/smoke.json" 2>"$RAW/smoke.err"; echo "smoke exit=$?" >> "$RAW/smoke.err"
if grep -qiE "$DRV|does not exist|^Error" "$RAW/smoke.err" || ! grep -q "smoke exit=0" "$RAW/smoke.err"; then echo "STOP: A6 smoke failed (Method A unavailable)"; exit 4; fi
echo "A6 Method A available"
AUD0=$(date '+%m/%d/%Y %H:%M:%S')

start_falco(){ # $1=window $2=raw base; rest = -r args
  local M=$1 base=$2; shift 2
  falco -o engine.kind=modern_ebpf -M "$M" -o json_output=true -o stdout_output.enabled=true -o rule_matching=all -o log_level=info \
    "$@" >"$RAW/${base}_raw.json" 2>"$RAW/${base}_falco.err" &
  FPID=$!; sleep 4
  if ! kill -0 "$FPID" 2>/dev/null || grep -qiE "$DRV|does not exist|^Error" "$RAW/${base}_falco.err"; then echo "STOP: temp Falco not running ($base)"; return 1; fi
  return 0; }

# ---- B. DIAG-FIELDS
if start_falco 90 diag_fields -r /etc/falco/falco_rules.yaml -r "$DIAG"; then
  for i in $(seq 1 "$N"); do
    TOK=DIAG_$(date +%s)_r$i; echo "TOK=$TOK" >> "$RAW/diag_fields_tok.txt"
    docker exec falco-lab-target python3 -c "import os,sys
fd=os.memfd_create('runc_cloned:/proc/self/exe'); os.write(fd,open('/bin/echo','rb').read()); os.execve(fd,['x',sys.argv[1]],{})" "$TOK" \
      >> "$RAW/diag_fields_payload_stdout.txt" 2>&1; sleep 1
  done
  wait "$FPID"; echo "falco exit status: $?" >> "$RAW/diag_fields_falco.err"
else echo "B FAILED" >> "$RAW/STOPS.txt"; fi

# ---- C. NT-B4 / NT-B1 / NT-B2
if start_falco 150 branch_isolation -r /etc/falco/falco_rules.yaml -r "$DIAG"; then
  PY=/usr/local/bin/python3; docker exec falco-lab-target test -x "$PY" || PY=python3
  for i in $(seq 1 "$N"); do
    TOK=NTB4_$(date +%s)_r$i; echo "$TOK" >> "$RAW/branch_toks.txt"
    docker exec falco-lab-target python3 -c "import os,sys
fd=os.memfd_create('not_runc_name'); os.write(fd,open('/bin/echo','rb').read())
os.execve(fd,['memfd:runc_cloned:/proc/self/exe',sys.argv[1]],{})" "$TOK" >> "$RAW/branch_payload_stdout.txt" 2>&1; sleep 1
    TOK=NTB1_$(date +%s)_r$i; echo "$TOK" >> "$RAW/branch_toks.txt"
    docker exec falco-lab-target python3 -c "import os,sys
fd=os.memfd_create('runc'); os.write(fd,open('/bin/echo','rb').read()); os.execve(fd,['x',sys.argv[1]],{})" "$TOK" >> "$RAW/branch_payload_stdout.txt" 2>&1; sleep 1
    TOK=NTB2_$(date +%s)_r$i; echo "$TOK (parent=$PY)" >> "$RAW/branch_toks.txt"
    docker exec falco-lab-target bash -c 'cp "'"$PY"'" /tmp/runc 2>/dev/null; exec -a runc /tmp/runc -c "import os,sys
fd=os.memfd_create(\"benign_b2\"); os.write(fd,open(\"/bin/echo\",\"rb\").read()); os.execve(fd,[\"x\",sys.argv[1]],{})" "$0"' "$TOK" >> "$RAW/branch_payload_stdout.txt" 2>&1; sleep 1
  done
  wait "$FPID"; echo "falco exit status: $?" >> "$RAW/branch_isolation_falco.err"
else echo "C FAILED" >> "$RAW/STOPS.txt"; fi
if [ -s "$RAW/auditd_execve_rules.txt" ]; then ausearch -sc execveat -ts "$AUD0" > "$RAW/auditd_execveat.txt" 2>&1; fi

# ---- D. R4 A/B/D/E
if start_falco 150 r4_scenarios -r /etc/falco/falco_rules.yaml -r rules/custom_rules.yaml -r rules/candidate_rules_v2.yaml; then
  for i in $(seq 1 "$N"); do
    TOK=R4A_$(date +%s)_r$i; echo "$TOK" >> "$RAW/r4_toks.txt"; docker exec falco-lab-target python3 -c "import os,sys
fd=os.memfd_create('runc_cloned:/proc/self/exe'); os.write(fd,open('/bin/echo','rb').read()); os.execve(fd,['x',sys.argv[1]],{})" "$TOK" >> "$RAW/r4_payload_stdout.txt" 2>&1; sleep 1
    TOK=R4B_$(date +%s)_r$i; echo "$TOK" >> "$RAW/r4_toks.txt"; docker exec falco-lab-target python3 -c "import os,sys
fd=os.memfd_create('falco_benign_memfd'); os.write(fd,open('/bin/echo','rb').read()); os.execve(fd,['x',sys.argv[1]],{})" "$TOK" >> "$RAW/r4_payload_stdout.txt" 2>&1; sleep 1
    TOK=R4D_$(date +%s)_r$i; echo "$TOK" >> "$RAW/r4_toks.txt"; docker exec falco-lab-target /bin/echo "$TOK" >> "$RAW/r4_payload_stdout.txt" 2>&1; sleep 1
    TOK=R4E_$(date +%s)_r$i; echo "$TOK" >> "$RAW/r4_toks.txt"; docker exec falco-lab-target bash -c 'cp /bin/echo /tmp/runc && exec -a runc /tmp/runc "$1"' _ "$TOK" >> "$RAW/r4_payload_stdout.txt" 2>&1; sleep 1
  done
  wait "$FPID"; echo "falco exit status: $?" >> "$RAW/r4_falco.err"
else echo "D FAILED" >> "$RAW/STOPS.txt"; fi

# ---- G cleanup + I verify
docker exec falco-lab-target rm -f /tmp/runc 2>/dev/null || true
sha256sum /etc/falco/falco_rules.yaml > "$RAW/ruleset_hash_after.txt"
ls -A /etc/falco/rules.d > "$RAW/rulesd_after.txt"
( cd "$RAW" && find . -type f ! -name SHA256SUMS.txt -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt )
chown -R 1000:1000 "$RAW"; chmod -R a-w "$RAW"
echo "DONE $RAW"
