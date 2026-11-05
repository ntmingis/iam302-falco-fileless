#!/usr/bin/env bash
# e9_proc_sampler.sh <out.tsv> — every 0.5 s log: ms, container, init_pid, shim_pid(ppid of init), pidns, cgroup, apparmor
OUT=$1
while :; do
  ms=$(date +%s%3N)
  for c in falco-lab-target falco-lab-client; do
    read -r pid prof < <(docker inspect -f '{{.State.Pid}} {{.AppArmorProfile}}' "$c" 2>/dev/null) || continue
    [ -n "$pid" ] && [ "$pid" != 0 ] || continue
    ppid=$(awk '{print $4}' /proc/$pid/stat 2>/dev/null)
    ns=$(readlink /proc/$pid/ns/pid 2>/dev/null); cg=$(head -1 /proc/$pid/cgroup 2>/dev/null)
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$ms" "$c" "$pid" "$ppid" "$ns" "$cg" "${prof:-<none>}"
  done >> "$OUT"
  sleep 0.5
done
