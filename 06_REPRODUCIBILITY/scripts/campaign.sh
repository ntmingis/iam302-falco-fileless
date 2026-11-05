#!/usr/bin/env bash
# campaign.sh - dot do con lai (E1-DEV, E2 day du, E3 custom, E3 bo tro rule_matching=all, E5):
#   sudo ./campaign.sh 2>&1 | tee -a results/campaign_$(date +%Y%m%d_%H%M%S).log
# Tuan tu, dung o buoc loi dau tien. trap EXIT luon dua ve baseline: ruleset default + rule_matching first,
#   giu falcoctl-artifact-follow dung, preflight default. Khong chay song song workload nao khac.
# SKIP="dev e2d ..." de bo qua buoc da co evidence hop le (id buoc in o dau moi dong [STEP]).
set -u
cd "$(dirname "$0")"
[ "$(id -u)" -eq 0 ] || { echo "can sudo"; exit 1; }
E1="memfd shm_host shm_ctr shm_ctr_exec procfd_link procfd_nolink procfd_drop python curl preload ptrace"
E4="e4_memfd_execveat e4_procfd_argv0 e4_shm_argv0 e4_python_stdin e4_curl_script e4_curl_sh e4_preload_env"
DEV="dev_memfd_runcname"
T3="procfd_link procfd_nolink procfd_drop e4_procfd_argv0"
SKIP=${SKIP:-}
FAILED=""

back_to_default(){ echo "[campaign] khoi phuc baseline default"; ./ruleset.sh default first >/dev/null && ./preflight.sh default | tail -1; }
trap back_to_default EXIT; trap 'exit 130' INT TERM HUP

step(){ local id=$1; shift
  case " $SKIP " in *" $id "*) echo "[STEP $id] BO QUA (SKIP)"; return 0;; esac
  echo "[STEP $id] $(date '+%F %T') $*"
  if "$@"; then echo "[STEP $id] OK $(date '+%T')"; else echo "[STEP $id] LOI rc=$? -> dung campaign"; FAILED=$id; exit 1; fi; }

systemctl stop falcoctl-artifact-follow
# ---- default
step def   ./ruleset.sh default first
step pfd   ./preflight.sh default
step dev   env REPS=5 TAG=dev TECHS="$DEV" ./run_e1.sh
step e2d   env ROUNDS=10 CHURN=50 ./run_e2.sh
# ---- custom (rule_matching first = mac dinh Falco)
step cus   ./ruleset.sh custom first
step pfc   ./preflight.sh custom
step e1c   env RULESET=custom REPS=5 TECHS="$E1" ./run_e1.sh
step e4c   env RULESET=custom REPS=5 TAG=e4 TECHS="$E4" ./run_e1.sh
step devc  env RULESET=custom REPS=5 TAG=dev TECHS="$DEV" ./run_e1.sh
step e2c   env RULESET=custom ROUNDS=10 CHURN=50 ./run_e2.sh
# ---- bo tro: custom + rule_matching all (do hieu ung che rule cua 'first' tren T3)
step cusa  ./ruleset.sh custom all
step t3a   env RULESET=custom REPS=5 TAG=all_t3 TECHS="$T3" ./run_e1.sh
# ---- E5 tren baseline default
step def2  ./ruleset.sh default first
step pfd2  ./preflight.sh default
step e5    env REPS=5 ./run_e5.sh
echo "[campaign] XONG tat ca buoc"
