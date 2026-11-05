#!/usr/bin/env bash
# e8_run.sh <cond> <rules...> — RC4 E8 independent external variants (run as root).
# Executes ONLY the commands in rc4/tables/e8_selection.csv (include=yes), verbatim, n=REPS (5), inside lab containers
# on falco-lab (Internal=true). Falco: falco-modern-bpf stopped; one foreground falco with explicit -r, rule_matching=all,
# JSON on stdout timestamped on receipt by host clock. Afterwards the service is started again.
set -u
export LC_ALL=C
cd /home/labuser/lab/falco_lab_containers
COND=${1:?cond}; shift
REPS=${REPS:-5}
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
OUT=rc4/runs_out/e8_${COND}_$(date -u +%Y%m%dT%H%M%SZ); mkdir -p "$OUT"
EG=rc4/external/event-generator_v0.13.0/bin/event-generator; SO=rc4/external/art_build/T1574006.so
MIR=rc4/external/art_d0cc590b/src
RARGS=(); for r in "$@"; do RARGS+=(-r "$r"); done
[ "$(docker network inspect falco-lab --format '{{.Internal}}')" = true ] || { echo "network not internal"; exit 5; }
{ echo "cond=$COND reps=$REPS started=$(date -Is)"; sha256sum "$@" rc4/tables/e8_selection.csv "$EG" "$SO" $MIR/*.sh; } > "$OUT/manifest.txt"
falco $(for r in "$@"; do printf -- '-V %s ' "$r"; done) > "$OUT/validate.txt" 2>&1 || { echo VALIDATE FAILED; exit 5; }
./labctl.sh up > "$OUT/labctl_up.txt" 2>&1
docker cp "$EG" falco-lab-target:/tmp/event-generator; docker cp "$SO" falco-lab-target:/tmp/T1574006.so
docker exec falco-lab-target sh -c 'grep " /dev/shm " /proc/mounts' > "$OUT/target_devshm_mount.txt"
docker rm -f falco-lab-e8mirror >/dev/null 2>&1
docker create --name falco-lab-e8mirror --network falco-lab falco-lab-target python3 -m http.server 8080 --directory /tmp/srv > /dev/null
mkdir -p "$OUT/srv"; cp $MIR/echo-art-fish.sh $MIR/pipe-to-shell.sh "$OUT/srv/"; docker cp "$OUT/srv" falco-lab-e8mirror:/tmp/srv
docker start falco-lab-e8mirror > /dev/null; sleep 2
docker exec falco-lab-client curl -sS -o /dev/null -w '%{http_code}\n' http://falco-lab-e8mirror:8080/pipe-to-shell.sh > "$OUT/mirror_check.txt" 2>&1
systemctl stop falco-modern-bpf; sleep 2
( falco -o engine.kind=modern_ebpf -o rule_matching=all -o json_output=true -o stdout_output.enabled=true -o file_output.enabled=false "${RARGS[@]}" 2> "$OUT/falco_stderr.txt" \
  | python3 -u -c 'import sys,time
for l in sys.stdin: sys.stdout.write("%d\t%s"%(time.time_ns()//1000000,l))' > "$OUT/falco_rx.log" ) &
for _ in $(seq 60); do grep -q 'Opening .* source\|Loaded event sources' "$OUT/falco_stderr.txt" && break; sleep 1; done; sleep 8
FP=$(pgrep -f "falco -o engine.kind=modern_ebpf -o rule_matching=all -o json_output=true" | head -1)
[ -n "$FP" ] || { echo "FALCO NOT RUNNING"; systemctl start falco-modern-bpf; exit 7; }
echo "test_id,rep,container,start_ms,end_ms,exit_code" > "$OUT/runs.csv"
mapfile -t ROWS < <(python3 -I -c 'import csv,sys
for r in csv.DictReader(open(sys.argv[1])):
    if r["include"]=="yes": print("\x1f".join([r["test_id"],r["container"],r["command"]]))' rc4/tables/e8_selection.csv)
for rep in $(seq 1 "$REPS"); do
  for row in "${ROWS[@]}"; do
    IFS=$'\x1f' read -r tid ctr cmd <<< "$row"
    safe=$(echo "$tid" | tr -c 'A-Za-z0-9._\n' '_')
    s=$(date +%s%3N)
    case "$tid" in
      "T1574.006#1")
        docker rm -f falco-lab-e8-ldso >/dev/null 2>&1
        docker create --name falco-lab-e8-ldso --network falco-lab falco-lab-target sh -c "$cmd" >/dev/null
        docker cp "$SO" falco-lab-e8-ldso:/tmp/T1574006.so
        docker start -a falco-lab-e8-ldso > "$OUT/${safe}_${rep}.out" 2>&1; rc=$?
        docker rm -f falco-lab-e8-ldso >/dev/null 2>&1 ;;
      "T1059.006#4")
        printf 'exit\nexit\n' | timeout 20 docker exec -i "$ctr" sh -c "$cmd" > "$OUT/${safe}_${rep}.out" 2>&1; rc=$? ;;
      *)
        timeout 60 docker exec "$ctr" sh -c "$cmd" > "$OUT/${safe}_${rep}.out" 2>&1; rc=$? ;;
    esac
    sleep 3; e=$(date +%s%3N)
    echo "$tid,$rep,$ctr,$s,$e,$rc" >> "$OUT/runs.csv"; echo "[$COND $tid #$rep] rc=$rc"
    sleep 2
  done
done
kill -INT "$FP"; sleep 5
docker rm -f falco-lab-e8mirror > /dev/null 2>&1
docker exec falco-lab-target rm -f /tmp/event-generator /tmp/T1574006.so
systemctl start falco-modern-bpf; sleep 3
./labctl.sh up > "$OUT/labctl_restore.txt" 2>&1
echo "finished=$(date -Is) falco-modern-bpf=$(systemctl is-active falco-modern-bpf) internal=$(docker network inspect falco-lab --format '{{.Internal}}')" >> "$OUT/manifest.txt"
( cd "$OUT" && find . -type f ! -name SHA256SUMS.txt -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt )
chown -R 1000:1000 "$OUT"
echo "DONE $OUT"
