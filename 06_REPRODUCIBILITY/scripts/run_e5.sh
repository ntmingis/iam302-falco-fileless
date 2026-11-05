#!/usr/bin/env bash
# run_e5.sh v1 - E5 overhead, chay tu falco_lab_containers/:  sudo REPS=5 ./run_e5.sh
# Cau hinh (cung workload, xen ke thu tu theo vong):
#   none   = Falco dung + audit tat (auditctl -e 0)      -> khong giam sat
#   falco  = Falco chay + audit tat
#   auditd = Falco dung + audit bat (rule lab)
#   both   = Falco chay + audit bat (trang thai lab binh thuong)
# THAY DOI TAM THOI BAO MAT HOST: dung falco-modern-bpf va tat audit trong cua so do. trap EXIT luon khoi phuc:
#   start falco-modern-bpf (giu falcoctl-artifact-follow nhu truoc) + auditctl -e 1.
# Workload chuan (giong het moi lan): exec loop trong container, churn docker run --rm, doc file bang python.
# Do: runtime tung phan, CPU host trung binh/dinh (/proc/stat, mau 200 ms), CPU-giay + RSS cua falco/auditd,
#   audit lost delta va backlog toi da.
set -u
export LC_ALL=C   # tranh dau phay thap phan (locale vi_VN) lam vo cot CSV - loi gap o e5_20261021_013631
cd "$(dirname "$0")"
REPS=${REPS:-5}; EXEC_N=${EXEC_N:-10000}; CHURN_N=${CHURN_N:-50}; READ_N=${READ_N:-20000}; SETTLE=${SETTLE:-10}
CONFIGS=(none falco auditd both)
[ "$(id -u)" -eq 0 ] || { echo "can sudo"; exit 1; }
[ "$(auditctl -s | awk '/^enabled/{print $2}')" = 1 ] || { echo "audit dang khong bat (enabled!=1) -> dung lai"; exit 1; }
systemctl is-active --quiet falco-modern-bpf || { echo "falco khong active luc bat dau -> dung lai"; exit 1; }
[ -z "$(ls -A /etc/falco/rules.d 2>/dev/null)" ] && [ ! -f /etc/falco/config.d/98-lab-rule-matching.yaml ] || { echo "E5 do tren baseline default: chay sudo ./ruleset.sh default first truoc"; exit 1; }
docker ps --format '{{.Names}}' | grep -E '^falco-lab-e2-' && { echo "co workload E2 dang chay -> dung lai"; exit 1; }
OUT=results/e5_$(date +%Y%m%d_%H%M%S)${TAG:+_$TAG}; mkdir -p "$OUT"
FOLLOW_WAS=$(systemctl is-active falcoctl-artifact-follow)

{ echo "run_id=$(basename "$OUT")"; echo "reps=$REPS exec_n=$EXEC_N churn_n=$CHURN_N read_n=$READ_N settle=$SETTLE configs=${CONFIGS[*]}"
  falco --version | grep -i 'falco version'; uname -r; runc --version | head -1; containerd --version
  docker version --format 'docker={{.Server.Version}}'; nproc; free -m | sed -n 2p
  echo "falcoctl-artifact-follow=$FOLLOW_WAS"
  sha256sum /etc/falco/falco.yaml /etc/falco/falco_rules.yaml /etc/falco/config.d/* /etc/falco/rules.d/* \
    /etc/audit/rules.d/*.rules run_e5.sh parse_e5.py 2>/dev/null; auditctl -l; auditctl -s
  echo "loadavg_start=$(cat /proc/loadavg)"; } > "$OUT/versions.txt" 2>&1

falco_on(){ local t0; t0=$(date '+%Y-%m-%d %H:%M:%S'); systemctl start falco-modern-bpf
  [ "$FOLLOW_WAS" = active ] || systemctl stop falcoctl-artifact-follow
  for _ in $(seq 30); do journalctl -u falco-modern-bpf --since "$t0" -o cat --no-pager | grep -q 'Loaded event sources' && return 0; sleep 1; done; return 1; }
falco_off(){ systemctl stop falco-modern-bpf; [ "$FOLLOW_WAS" = active ] || systemctl stop falcoctl-artifact-follow; }
restore(){ auditctl -e 1 >/dev/null; systemctl is-active --quiet falco-modern-bpf || falco_on
  echo "KHOI PHUC: falco=$(systemctl is-active falco-modern-bpf) audit_enabled=$(auditctl -s | awk '/^enabled/{print $2}') follow=$(systemctl is-active falcoctl-artifact-follow)" | tee -a "$OUT/versions.txt"; }
trap restore EXIT; trap 'exit 130' INT TERM HUP

set_config(){ case "$1" in
  none)   falco_off; auditctl -e 0 >/dev/null;;
  falco)  auditctl -e 0 >/dev/null; systemctl is-active --quiet falco-modern-bpf || falco_on;;
  auditd) falco_off; auditctl -e 1 >/dev/null;;
  both)   auditctl -e 1 >/dev/null; systemctl is-active --quiet falco-modern-bpf || falco_on;; esac; }

pidcpu(){ local p; p=$(pgrep -xo "$1") || { echo 0; return; }; awk '{print $14+$15}' "/proc/$p/stat"; }
pidrss(){ local p; p=$(pgrep -xo "$1") || { echo 0; return; }; awk '/VmRSS/{print $2}' "/proc/$p/status"; }
TCK=$(getconf CLK_TCK)

w_exec(){ docker exec falco-lab-target bash -c "for i in \$(seq $EXEC_N); do /bin/true; done"; }
w_churn(){ local i; for i in $(seq "$CHURN_N"); do docker run --rm --network none ubuntu:22.04 true || return 1; done; }
w_read(){ docker exec falco-lab-target python3 -c "import os
n=0
for root,_,fs in os.walk('/usr'):
    for f in fs:
        p=os.path.join(root,f)
        try:
            with open(p,'rb') as h: h.read(4096)
        except OSError: pass
        n+=1
        if n>=$READ_N: raise SystemExit(0)"; }

measure(){ # $1=config $2=rep $3=part
  local s e c0 c1 a0 a1 l0 l1 smp="$OUT/cpu_${1}_${2}_${3}.txt"
  ( while :; do head -1 /proc/stat; sleep 0.2; done ) > "$smp" & local sp=$!
  c0=$(pidcpu falco); a0=$(pidcpu auditd); l0=$(auditctl -s | awk '/^lost/{print $2}')
  s=$(date +%s%3N); "w_$3" > /dev/null 2>&1; local rc=$?; e=$(date +%s%3N)
  c1=$(pidcpu falco); a1=$(pidcpu auditd); l1=$(auditctl -s | awk '/^lost/{print $2}'); local bl; bl=$(auditctl -s | awk '/^backlog /{print $2}')
  kill $sp 2>/dev/null; wait $sp 2>/dev/null
  local cpu; cpu=$(python3 - "$smp" <<'EOF'
import sys
r = [list(map(int, l.split()[1:])) for l in open(sys.argv[1]) if l.startswith("cpu ")]
u = []
for a, b in zip(r, r[1:]):
    tot = sum(b) - sum(a); idle = (b[3] + b[4]) - (a[3] + a[4])
    if tot > 0: u.append(100 * (tot - idle) / tot)
tot = sum(r[-1]) - sum(r[0]); idle = (r[-1][3] + r[-1][4]) - (r[0][3] + r[0][4])
print(f"{100*(tot-idle)/tot:.2f},{max(u):.2f}" if len(r) > 1 and tot > 0 else ",")
EOF
)
  echo "$1,$2,$3,$s,$e,$((e-s)),$rc,$cpu,$(awk "BEGIN{printf \"%.3f\",($c1-$c0)/$TCK}"),$(awk "BEGIN{printf \"%.3f\",($a1-$a0)/$TCK}"),$(pidrss falco),$(pidrss auditd),$((l1-l0)),$bl" >> "$OUT/e5_runs.csv"; }

echo "config,rep,part,start_ms,end_ms,runtime_ms,exit_code,cpu_avg_pct,cpu_peak_pct,falco_cpu_s,auditd_cpu_s,falco_rss_kb,auditd_rss_kb,audit_lost_delta,audit_backlog_end" > "$OUT/e5_runs.csv"
./labctl.sh up >/dev/null 2>&1 || { echo "labctl up loi"; exit 1; }; sleep 5
echo "[warm-up]"; for p in exec churn read; do "w_$p" >/dev/null 2>&1; done
for r in $(seq 1 "$REPS"); do
  for k in 0 1 2 3; do c=${CONFIGS[$(( (k + r - 1) % 4 ))]}      # xoay thu tu cau hinh theo vong
    set_config "$c" || { echo "set_config $c loi"; exit 1; }; sleep "$SETTLE"
    for p in exec churn read; do measure "$c" "$r" "$p"; done
    echo "[r$r $c] $(tail -3 "$OUT/e5_runs.csv" | cut -d, -f3,6 | tr '\n' ' ')"
  done
done
echo "loadavg_end=$(cat /proc/loadavg)" >> "$OUT/versions.txt"
echo "Xong -> python3 parse_e5.py $OUT analysis/$(basename "$OUT")"
