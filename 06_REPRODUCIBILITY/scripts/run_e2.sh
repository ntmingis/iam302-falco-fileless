#!/usr/bin/env bash
# run_e2.sh v1 - E2 false-positive baseline, chay tu falco_lab_containers/:  sudo ROUNDS=10 CHURN=50 ./run_e2.sh
#   RULESET=default|custom (nhan, phai khop rules.d), TAG=pilot (hau to thu muc)
# Chi workload LANH TINH, khong co payload ky thuat nao. Container dat ten falco-lab-e2-* de quy alert.
# Moi vong: lifecycle web+db (run -d / stop / rm), HTTP noi bo, SQL, build job (gcc compile + chay binary),
#   python (script file, -m, -c), churn = CHURN lan `docker run --rm`.
# Mang: web/db/client tren falco-lab (Internal=true); build/churn --network none.
set -u
cd "$(dirname "$0")"
ROUNDS=${ROUNDS:-10}; CHURN=${CHURN:-50}; HTTP_N=${HTTP_N:-20}; RULESET=${RULESET:-default}
FJ=/var/log/falco/events.json; AL=/var/log/audit/audit.log
WEB_IMG=nginx:1.27-alpine; DB_IMG=postgres:16-alpine; GCC_IMG=gcc:13; CHURN_IMG=ubuntu:22.04
[ "$(id -u)" -eq 0 ] || { echo "can sudo"; exit 1; }
[ -x ./labctl.sh ] || { echo "chay trong thu muc co labctl.sh"; exit 1; }
[ -f "$FJ" ] || { echo "thieu $FJ"; exit 1; }
for i in $WEB_IMG $CHURN_IMG falco-lab-client:latest falco-lab-target:latest; do
  docker image inspect "$i" >/dev/null 2>&1 || { echo "thieu image $i"; exit 1; }; done
# build job: gcc that neu co image gcc; neu khong -> artifact mo phong (copy ELF moi vao upper layer roi chay)
# database: postgres neu co image; neu khong -> bo qua workload sql (ghi db_mode=none trong manifest)
if docker image inspect "$DB_IMG" >/dev/null 2>&1; then DB_MODE=postgres; else DB_MODE=none; echo "[!] thieu $DB_IMG -> bo qua workload database"; fi
if docker image inspect "$GCC_IMG" >/dev/null 2>&1; then BUILD_MODE=gcc; BUILD_IMG=$GCC_IMG; else BUILD_MODE=artifact; BUILD_IMG=$CHURN_IMG; fi
RD=$(ls -A /etc/falco/rules.d 2>/dev/null)
if [ "$RULESET" = default ] && [ -n "$RD" ]; then echo "RULESET=default nhung rules.d co: $RD"; exit 1; fi
if [ "$RULESET" != default ] && [ -z "$RD" ]; then echo "RULESET=$RULESET nhung rules.d rong"; exit 1; fi
OUT=results/e2_${RULESET}_$(date +%Y%m%d_%H%M%S)${TAG:+_$TAG}; mkdir -p "$OUT"

{ echo "ruleset=$RULESET"; echo "run_id=$(basename "$OUT")"; echo "rounds=$ROUNDS churn=$CHURN http_n=$HTTP_N build_mode=$BUILD_MODE build_img=$BUILD_IMG db_mode=$DB_MODE"
  falco --version | grep -i 'falco version'; uname -r; runc --version | head -1; containerd --version
  docker version --format 'docker={{.Server.Version}}'
  echo "falcoctl-artifact-follow=$(systemctl is-active falcoctl-artifact-follow)"
  echo "rule_matching=$(sed -n 's/^rule_matching: *//p' /etc/falco/config.d/98-lab-rule-matching.yaml 2>/dev/null | grep . || echo 'first (mac dinh)')"
  sha256sum /etc/falco/falco.yaml /etc/falco/falco_rules.yaml /etc/falco/falco_rules.local.yaml /etc/falco/config.d/* \
    /etc/audit/rules.d/*.rules /etc/falco/rules.d/* run_e2.sh parse_e2.py labctl.sh 2>/dev/null
  for i in $WEB_IMG $BUILD_IMG $CHURN_IMG falco-lab-client:latest falco-lab-target:latest; do
    docker image inspect "$i" --format "image $i {{.Id}}"; done
  [ "$DB_MODE" = postgres ] && docker image inspect "$DB_IMG" --format "image $DB_IMG {{.Id}}"
  auditctl -l; docker network inspect falco-lab --format 'Internal={{.Internal}}'; } > "$OUT/versions.txt" 2>&1
auditctl -s > "$OUT/audit_status_start.txt"

mark(){ stat -c '%i %s' "$1"; }
slice(){ local ino=${2% *} sz=${2#* } old
  if [ "$(stat -c %i "$1")" = "$ino" ]; then tail -c +$((sz+1)) "$1"
  else old=$(find "$(dirname "$1")" -maxdepth 1 -inum "$ino" | head -1)
       if [ -n "$old" ]; then tail -c +$((sz+1)) "$old"; else echo "[!] $1 xoay vong >1 lan, thieu du lieu" >&2; fi
       cat "$1"; fi > "$3"; }
FJ0=$(mark "$FJ"); AL0=$(mark "$AL")
tail -n0 -F "$FJ" 2>/dev/null | python3 -u -c 'import sys,time
for l in sys.stdin: sys.stdout.write("%d\t%s"%(time.time_ns()//1000000,l))' > "$OUT/falco_rx.log" &
cleanup(){ docker rm -f falco-lab-e2-web falco-lab-e2-db >/dev/null 2>&1; }
finish(){ cleanup; pkill -f "tail -n0 -F $FJ" 2>/dev/null
  slice "$FJ" "$FJ0" "$OUT/falco_events.json"; slice "$AL" "$AL0" "$OUT/audit.log"; auditctl -s > "$OUT/audit_status_end.txt"
  echo "Snapshot log -> $OUT"; }
trap finish EXIT

HELLO_C='#include <stdio.h>
int main(void){ puts("E2_BUILD_OK"); return 0; }'
PY_SCRIPT='import json, hashlib
d = {"k": list(range(10))}
print("E2_PY_SCRIPT_OK", hashlib.sha256(json.dumps(d).encode()).hexdigest()[:8])'

w_lifecycle_up(){ docker run -d --name falco-lab-e2-web --network falco-lab "$WEB_IMG" >/dev/null || return 1
  [ "$DB_MODE" = postgres ] || return 0
  docker run -d --name falco-lab-e2-db --network falco-lab -e POSTGRES_PASSWORD="${E2_DB_PASSWORD:?set E2_DB_PASSWORD to a throwaway value - see README}" "$DB_IMG" >/dev/null &&
  for _ in $(seq 60); do docker exec falco-lab-e2-db pg_isready -U postgres -q 2>/dev/null && return 0; sleep 1; done; return 1; }
w_http(){ local i; for i in $(seq "$HTTP_N"); do docker exec falco-lab-client curl -fsS -o /dev/null http://falco-lab-e2-web/ || return 1; done; }
w_sql(){ docker exec falco-lab-e2-db psql -U postgres -qtA -c \
  "CREATE TABLE IF NOT EXISTS e2(id serial, v text); INSERT INTO e2(v) SELECT md5(g::text) FROM generate_series(1,1000) g; SELECT count(*) FROM e2;"; }
w_build(){ if [ "$BUILD_MODE" = gcc ]; then docker run --rm --network none --name "falco-lab-e2-build-$1" "$GCC_IMG" bash -c \
  'printf "%s\n" "$1" > /tmp/h.c && gcc -O2 -o /tmp/hello /tmp/h.c && /tmp/hello' _ "$HELLO_C"
  else docker run --rm --network none --name "falco-lab-e2-build-$1" "$BUILD_IMG" bash -c \
  'mkdir -p /tmp/out && cp /bin/true /tmp/out/app && chmod 0755 /tmp/out/app && /tmp/out/app && echo E2_BUILD_OK'; fi; }
w_python(){ docker exec falco-lab-target bash -c 'printf "%s\n" "$1" > /tmp/e2.py && python3 /tmp/e2.py && rm -f /tmp/e2.py' _ "$PY_SCRIPT" &&
  echo '{"a":1}' | docker exec -i falco-lab-target python3 -m json.tool >/dev/null &&
  docker exec falco-lab-target python3 -c 'import platform; print("E2_PY_C_OK", platform.python_version())'; }
w_churn(){ local i; for i in $(seq "$CHURN"); do
  docker run --rm --network none --name "falco-lab-e2-churn-$1-$i" "$CHURN_IMG" true || return 1; done; }
w_lifecycle_down(){ local c=falco-lab-e2-web; [ "$DB_MODE" = postgres ] && c="$c falco-lab-e2-db"
  docker stop -t 5 $c >/dev/null && docker rm $c >/dev/null; }

# so lan workload trong 1 lan goi (mau so FP)
NC=1; [ "$DB_MODE" = postgres ] && NC=2
declare -A UNITS=([lifecycle_up]=$NC [http]=$HTTP_N [sql]=1 [build]=1 [python]=3 [churn]=$CHURN [lifecycle_down]=$NC)
WL="lifecycle_up http sql build python churn lifecycle_down"; [ "$DB_MODE" = postgres ] || WL="lifecycle_up http build python churn lifecycle_down"
echo "workload,round,start_ms,end_ms,exit_code,units" > "$OUT/e2_runs.csv"
./labctl.sh up >/dev/null 2>&1 || { echo "labctl up loi"; exit 1; }; sleep 5; cleanup
for r in $(seq 1 "$ROUNDS"); do
  for w in $WL; do
    s=$(date +%s%3N); "w_$w" "$r" > "$OUT/${w}_${r}.out" 2>&1; rc=$?; sleep 2; e=$(date +%s%3N)
    echo "$w,$r,$s,$e,$rc,${UNITS[$w]}" >> "$OUT/e2_runs.csv"; echo "[r$r $w] exit=$rc"
    [ "$w" = lifecycle_up ] && [ $rc -ne 0 ] && { echo "lifecycle_up loi, bo vong $r"; cleanup; break; }
  done
done
echo "Xong -> python3 parse_e2.py $OUT analysis/$(basename "$OUT")"
