#!/usr/bin/env bash
# e7_run.sh <tetragon|tracee> — RC4 E7 second sensor, ONE sensor at a time (run as root).
# Falco service STOPPED for the whole run. Sensor runs in the foreground from its extracted, checksum-verified release
# directory (nothing copied into /usr/local or /etc; no systemd unit installed). Harness: run_e1.sh UNCHANGED,
# E1 11 + E4 7 + DEV-T1r, REPS=5. A sampler maps container IDs -> names. Afterwards: sensor stopped, residues removed,
# falco-modern-bpf started again.
set -u
export LC_ALL=C
cd /home/labuser/lab/falco_lab_containers
TOOL=${1:?tool}
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
OUT=rc4/runs_out/e7_${TOOL}_$(date -u +%Y%m%dT%H%M%SZ); mkdir -p "$OUT"
TECHS="memfd shm_host shm_ctr shm_ctr_exec procfd_link procfd_nolink procfd_drop python curl preload ptrace e4_memfd_execveat e4_procfd_argv0 e4_shm_argv0 e4_python_stdin e4_curl_script e4_curl_sh e4_preload_env dev_memfd_runcname"
TG=rc4/external/tetragon_v1.7.1/x/tetragon-v1.7.1-amd64
TR=rc4/external/tracee_v0.23.2/x/dist
[ "$(docker network inspect falco-lab --format '{{.Internal}}')" = true ] || exit 5
systemctl stop falco-modern-bpf; sleep 2; systemctl is-active --quiet falco-modern-bpf && exit 6
echo "tool=$TOOL started=$(date -Is) falco-modern-bpf=$(systemctl is-active falco-modern-bpf)" > "$OUT/manifest.txt"
( while :; do t=$(date +%s%3N); docker ps --no-trunc --format '{{.ID}} {{.Names}}' | sed "s/^/$t /"; sleep 1; done ) > "$OUT/container_ids.log" 2>/dev/null &
SAMP=$!
case "$TOOL" in
  tetragon)
    sha256sum $TG/usr/local/bin/tetragon >> "$OUT/manifest.txt"; $TG/usr/local/bin/tetragon --version >> "$OUT/manifest.txt" 2>&1
    $TG/usr/local/bin/tetragon --bpf-lib $TG/usr/local/lib/tetragon/bpf/ --export-filename "$PWD/$OUT/tetragon_events.json" \
      --export-file-compress=false --server-address "" --log-level info > "$OUT/sensor_stdout.txt" 2> "$OUT/sensor_stderr.txt" &
    SP=$!; READY='Listening for events|Starting process manager|Read ProcFS' ;;
  tracee)
    sha256sum $TR/tracee $TR/signatures/builtin.so >> "$OUT/manifest.txt"; $TR/tracee version >> "$OUT/manifest.txt" 2>&1
    EV=$($TR/tracee list 2>/dev/null | sed -n '/Signature Events/,/Syscall Events/p' | grep -E '^\| [a-z]' | awk -F'|' '{gsub(/ /,"",$2);print $2}' | paste -sd, -)
    echo "events=$EV" >> "$OUT/manifest.txt"
    ( $TR/tracee --signatures-dir $TR/signatures --events "$EV" --output json 2> "$OUT/sensor_stderr.txt" \
      | python3 -u -c 'import sys,time
for l in sys.stdin: sys.stdout.write("%d\t%s"%(time.time_ns()//1000000,l))' > "$OUT/tracee_rx.log" ) &
    SP=$!; READY='' ;;
  *) echo "unknown tool"; kill $SAMP; systemctl start falco-modern-bpf; exit 2 ;;
esac
sleep 30
alive=$(pgrep -f "$TG/usr/local/bin/tetragon --bpf-lib|$TR/tracee --signatures-dir" | head -1)
echo "sensor_pid=$alive" >> "$OUT/manifest.txt"
if [ -z "$alive" ]; then echo "SENSOR FAILED TO START"; tail -20 "$OUT/sensor_stderr.txt"; kill $SAMP; systemctl start falco-modern-bpf; exit 7; fi
REPS=5 TECHS="$TECHS" TAG="rc4_e7_${TOOL}" ./run_e1.sh > "$OUT/run_e1_console.txt" 2>&1; echo "run_e1 exit=$?" >> "$OUT/manifest.txt"
grep -h 'run_id=' results/e1_default_*_rc4_e7_${TOOL}/versions.txt >> "$OUT/manifest.txt" 2>/dev/null
pkill -INT -f "$TG/usr/local/bin/tetragon --bpf-lib|$TR/tracee --signatures-dir"; sleep 10
pkill -KILL -f "$TG/usr/local/bin/tetragon --bpf-lib|$TR/tracee --signatures-dir" 2>/dev/null
kill $SAMP
# residues (runtime only; nothing was installed)
rm -rf /sys/fs/bpf/tetragon /var/run/tetragon /tmp/tracee 2>/dev/null
{ echo "residue check:"; ls -d /sys/fs/bpf/tetragon /var/run/tetragon /tmp/tracee /usr/local/bin/tetragon /usr/local/bin/tracee /etc/tetragon /usr/lib/systemd/system/tetragon.service 2>&1; } >> "$OUT/manifest.txt"
systemctl start falco-modern-bpf; sleep 3
./labctl.sh up > "$OUT/labctl_restore.txt" 2>&1
echo "finished=$(date -Is) falco-modern-bpf=$(systemctl is-active falco-modern-bpf) internal=$(docker network inspect falco-lab --format '{{.Internal}}')" >> "$OUT/manifest.txt"
( cd "$OUT" && find . -type f ! -name SHA256SUMS.txt -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt )
chown -R 1000:1000 "$OUT"
echo "DONE $OUT"
