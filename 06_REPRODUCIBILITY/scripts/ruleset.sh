#!/usr/bin/env bash
# ruleset.sh - chuyen trang thai rule Falco cho thi nghiem:  sudo ./ruleset.sh <default|probe|custom> [first|all]
#   default : rules.d khong co file lab (baseline)
#   probe   : rules/lab_probe.yaml        -> /etc/falco/rules.d/lab_probe.yaml
#   custom  : rules/custom_rules.yaml     -> /etc/falco/rules.d/lab_custom_rules.yaml
#   first|all: rule_matching (mac dinh first = mac dinh Falco); all -> /etc/falco/config.d/98-lab-rule-matching.yaml
# Chi dong vao 3 file do script quan ly. Backup rules.d + config.d truoc khi doi. Validate truoc khi cai, restart Falco,
# cho Falco nap xong va kiem journal. Khong sua falco.yaml / falco_rules.yaml.
set -u
cd "$(dirname "$0")"
MODE=${1:-}; MATCH=${2:-first}
[ "$(id -u)" -eq 0 ] || { echo "can sudo"; exit 1; }
case "$MODE" in default) SRC="";; probe) SRC=rules/lab_probe.yaml;; custom) SRC=rules/custom_rules.yaml;;
  *) echo "usage: sudo ./ruleset.sh <default|probe|custom> [first|all]"; exit 1;; esac
case "$MATCH" in first|all) ;; *) echo "rule_matching phai la first|all"; exit 1;; esac
RD=/etc/falco/rules.d; CD=/etc/falco/config.d; MCF=$CD/98-lab-rule-matching.yaml
MANAGED="$RD/lab_probe.yaml $RD/lab_custom_rules.yaml"
LOG=results/ruleset_$(date +%Y%m%d_%H%M%S)_${MODE}_${MATCH}; mkdir -p "$LOG/before"
cp -a "$RD" "$CD" "$LOG/before/"

other=$(ls -A "$RD" | grep -vxE 'lab_probe.yaml|lab_custom_rules.yaml')
[ -z "$other" ] || { echo "rules.d co file khong do script quan ly: $other -> dung lai"; exit 1; }
if [ -n "$SRC" ]; then
  [ -f "$SRC" ] || { echo "thieu $SRC"; exit 1; }
  falco -V /etc/falco/falco_rules.yaml -V "$SRC" > "$LOG/validate.txt" 2>&1 || { echo "validate loi -> $LOG/validate.txt"; exit 1; }
  echo "validate OK: $SRC (canh bao, neu co, trong $LOG/validate.txt)"
fi

rm -f $MANAGED
case "$MODE" in probe) install -m 0644 "$SRC" "$RD/lab_probe.yaml";; custom) install -m 0644 "$SRC" "$RD/lab_custom_rules.yaml";; esac
if [ "$MATCH" = all ]; then printf 'rule_matching: all\n' > "$MCF"; chmod 0644 "$MCF"; else rm -f "$MCF"; fi

# falco-modern-bpf Wants= falcoctl-artifact-follow (PartOf) -> restart Falco bat lai follower; giu trang thai cu
FOLLOW_WAS=$(systemctl is-active falcoctl-artifact-follow); H0=$(sha256sum < /etc/falco/falco_rules.yaml)
T0=$(date '+%Y-%m-%d %H:%M:%S')
systemctl restart falco-modern-bpf
[ "$FOLLOW_WAS" = active ] || systemctl stop falcoctl-artifact-follow
for _ in $(seq 30); do journalctl -u falco-modern-bpf --since "$T0" -o cat --no-pager | grep -q 'Loaded event sources' && break; sleep 1; done
journalctl -u falco-modern-bpf --since "$T0" -o cat --no-pager | grep -vE '^\{' > "$LOG/falco_start.txt"
systemctl is-active --quiet falco-modern-bpf || { echo "FALCO KHONG ACTIVE -> xem $LOG/falco_start.txt"; exit 1; }
grep -q 'Loaded event sources' "$LOG/falco_start.txt" || { echo "Falco chua nap xong sau 30 s -> $LOG/falco_start.txt"; exit 1; }
grep -iE 'error|invalid' "$LOG/falco_start.txt" && { echo "co loi khi nap -> $LOG/falco_start.txt"; exit 1; }
[ "$(sha256sum < /etc/falco/falco_rules.yaml)" = "$H0" ] || { echo "falco_rules.yaml DA THAY DOI khi restart -> dung lai"; exit 1; }
echo "falcoctl-artifact-follow: truoc=$FOLLOW_WAS sau=$(systemctl is-active falcoctl-artifact-follow)"
{ echo "mode=$MODE rule_matching=$MATCH at=$(date -Is)"; ls -l "$RD" "$CD"
  sha256sum /etc/falco/falco_rules.yaml "$CD"/* "$RD"/* 2>/dev/null; } | tee "$LOG/state.txt"
echo "OK -> $LOG"
