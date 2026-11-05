#!/usr/bin/env bash
# e9_run.sh — RC4 E9 (run as root). Variants T1 T3b T4 T5 DEV-T1r, n=5, two container configs:
#  (a) default AppArmor: ./run_e1.sh (unchanged) ; (b) apparmor=unconfined: rc4/e9_harness/run_e1.sh (byte-identical copy)
#  driven by rc4/e9_harness/labctl.sh (variant: + --security-opt apparmor=unconfined on target/client only).
# Falco: installed falco-modern-bpf service, default ruleset (unchanged). A /proc sampler records init/shim PIDs.
set -u
export LC_ALL=C
cd /home/labuser/lab/falco_lab_containers
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
LOGD=rc4/logs/e9_$(date -u +%Y%m%dT%H%M%SZ); mkdir -p "$LOGD"
TECHS="memfd procfd_nolink python curl dev_memfd_runcname"
cmp run_e1.sh rc4/e9_harness/run_e1.sh || { echo "harness copy differs"; exit 2; }
systemctl is-active --quiet falco-modern-bpf || { echo "falco service not active"; exit 3; }
[ -z "$(ls -A /etc/falco/rules.d)" ] || exit 4
[ "$(docker network inspect falco-lab --format '{{.Internal}}')" = true ] || { echo "network not internal"; exit 5; }
{ echo "started=$(date -Is)"; sha256sum run_e1.sh rc4/e9_harness/run_e1.sh labctl.sh rc4/e9_harness/labctl.sh /etc/falco/falco_rules.yaml; } > "$LOGD/manifest.txt"
rc4/runs/e9_proc_sampler.sh "$LOGD/proc_map_default.tsv" & SP=$!
REPS=5 TECHS="$TECHS" TAG=rc4_e9_apparmor_default ./run_e1.sh > "$LOGD/run_default_console.txt" 2>&1; echo "default exit=$?" >> "$LOGD/manifest.txt"
kill $SP
mkdir -p rc4/e9_harness/results
rc4/runs/e9_proc_sampler.sh "$LOGD/proc_map_unconfined.tsv" & SP=$!
( cd rc4/e9_harness && REPS=5 TECHS="$TECHS" TAG=rc4_e9_apparmor_unconfined ./run_e1.sh ) > "$LOGD/run_unconfined_console.txt" 2>&1; echo "unconfined exit=$?" >> "$LOGD/manifest.txt"
kill $SP
docker inspect -f '{{.Name}} {{.AppArmorProfile}} priv={{.HostConfig.Privileged}} caps={{.HostConfig.CapAdd}} binds={{.HostConfig.Binds}}' falco-lab-target falco-lab-client >> "$LOGD/manifest.txt"
./labctl.sh up > "$LOGD/labctl_restore.txt" 2>&1
docker inspect -f '{{.Name}} {{.AppArmorProfile}}' falco-lab-target falco-lab-client >> "$LOGD/manifest.txt"
echo "network Internal=$(docker network inspect falco-lab --format '{{.Internal}}') finished=$(date -Is)" >> "$LOGD/manifest.txt"
chown -R 1000:1000 "$LOGD" rc4/e9_harness
echo "DONE $LOGD"
