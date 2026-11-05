#!/usr/bin/env bash
# fg_falco_harness.sh <cond_label> <rules...> — RC4 E6-dynamic runner (run as root).
# Stops falco-modern-bpf, starts ONE foreground falco (same /etc/falco/falco.yaml + config.d, so alerts go to
# /var/log/falco/events.json as in RC3) with explicit -r <rules...> and rule_matching=all, then drives the UNCHANGED
# harness: run_e1.sh (E1 11 + E4 7 + DEV-T1r, REPS=5) and run_e2.sh (ROUNDS=10 CHURN=50, RC3 parameters).
# Harness RULESET label stays "default" (rules.d is empty, which run_e1/run_e2 enforce); the condition is carried in
# TAG and in this script's manifest. Afterwards: stop the foreground falco, start falco-modern-bpf again.
set -u
export LC_ALL=C
cd /home/labuser/lab/falco_lab_containers
COND=${1:?cond}; shift
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
LOGD=rc4/logs/e6_${COND}_$(date -u +%Y%m%dT%H%M%SZ); mkdir -p "$LOGD"
TECHS_ALL="memfd shm_host shm_ctr shm_ctr_exec procfd_link procfd_nolink procfd_drop python curl preload ptrace e4_memfd_execveat e4_procfd_argv0 e4_shm_argv0 e4_python_stdin e4_curl_script e4_curl_sh e4_preload_env dev_memfd_runcname"
RARGS=(); for r in "$@"; do RARGS+=(-r "$r"); done
{ echo "cond=$COND started=$(date -Is)"; echo "rules=$*"; sha256sum "$@"; echo "rule_matching=all"; sha256sum /etc/falco/falco_rules.yaml; } > "$LOGD/manifest.txt"
falco $(for r in "$@"; do printf -- '-V %s ' "$r"; done) > "$LOGD/validate.txt" 2>&1 || { echo "VALIDATE FAILED"; cat "$LOGD/validate.txt"; exit 5; }
systemctl stop falco-modern-bpf; sleep 2
systemctl is-active --quiet falco-modern-bpf && { echo "falco-modern-bpf still active"; exit 6; }
falco -o engine.kind=modern_ebpf -o rule_matching=all "${RARGS[@]}" > "$LOGD/falco_stdout.txt" 2> "$LOGD/falco_stderr.txt" &
FPID=$!; echo "falco_pid=$FPID" >> "$LOGD/manifest.txt"
ok=0; for _ in $(seq 60); do grep -q 'Loaded event sources\|Enabled event sources\|Opening .* source' "$LOGD/falco_stderr.txt" "$LOGD/falco_stdout.txt" 2>/dev/null && { ok=1; break; }; kill -0 $FPID 2>/dev/null || break; sleep 1; done
sleep 5
if ! kill -0 $FPID 2>/dev/null || [ $ok -ne 1 ]; then echo "FOREGROUND FALCO FAILED TO START"; tail -20 "$LOGD/falco_stderr.txt"; systemctl start falco-modern-bpf; exit 7; fi
echo "foreground falco up (pid $FPID)"
REPS=5 TECHS="$TECHS_ALL" TAG="rc4_${COND}" ./run_e1.sh > "$LOGD/run_e1_console.txt" 2>&1; echo "run_e1 exit=$?" >> "$LOGD/manifest.txt"
ROUNDS=10 CHURN=50 TAG="rc4_${COND}" ./run_e2.sh > "$LOGD/run_e2_console.txt" 2>&1; echo "run_e2 exit=$?" >> "$LOGD/manifest.txt"
kill -0 $FPID 2>/dev/null && echo "falco alive at end: yes" >> "$LOGD/manifest.txt" || echo "falco alive at end: NO" >> "$LOGD/manifest.txt"
kill -INT $FPID; wait $FPID; echo "falco exit=$?" >> "$LOGD/manifest.txt"
systemctl start falco-modern-bpf; sleep 3
echo "falco-modern-bpf=$(systemctl is-active falco-modern-bpf) finished=$(date -Is)" >> "$LOGD/manifest.txt"
grep -h 'run_id=' results/e1_default_*_rc4_${COND}/versions.txt results/e2_default_*_rc4_${COND}/versions.txt >> "$LOGD/manifest.txt" 2>/dev/null
chown -R 1000:1000 "$LOGD"
echo "DONE $LOGD"
