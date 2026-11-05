#!/usr/bin/env bash
# campaign_e2supp.sh (2026-10-22) - E2 bo sung DB (PostgreSQL 14) + build that (gcc/make), default roi custom:
#   sudo ./campaign_e2supp.sh
# Log console tu ghi vao results/campaign_e2supp_<time>.log (chay duoi root nen ghi duoc vao results/).
# Tuan tu, dung o buoc loi dau tien; trap EXIT luon dua ve baseline default/first + preflight default.
# Khong chay lai E1-E5 cu. Khong dong vao mang falco-lab (run_e2_supp.sh chi kiem Internal=true).
set -u
export LC_ALL=C
cd "$(dirname "$0")"
[ "$(id -u)" -eq 0 ] || { echo "can sudo"; exit 1; }
LOG=results/campaign_e2supp_$(date +%Y%m%d_%H%M%S).log
exec > >(tee -a "$LOG") 2>&1
back_to_default(){ echo "[campaign] khoi phuc baseline default"; ./ruleset.sh default first >/dev/null && ./preflight.sh default | tail -1
  echo "[campaign] follower=$(systemctl is-active falcoctl-artifact-follow) falco=$(systemctl is-active falco-modern-bpf) auditd=$(systemctl is-active auditd)"
  chmod 0644 "$LOG"; }
trap back_to_default EXIT; trap 'exit 130' INT TERM HUP
step(){ local id=$1; shift
  echo "[STEP $id] $(date '+%F %T') $*"
  if "$@"; then echo "[STEP $id] OK $(date '+%T')"; else echo "[STEP $id] LOI rc=$? -> dung campaign"; exit 1; fi; }

systemctl stop falcoctl-artifact-follow
step def  ./ruleset.sh default first
step pfd  ./preflight.sh default
step e2sd env RULESET=default ROUNDS=10 ./run_e2_supp.sh
step cus  ./ruleset.sh custom first
step pfc  ./preflight.sh custom
step e2sc env RULESET=custom ROUNDS=10 ./run_e2_supp.sh
echo "[campaign] XONG"
