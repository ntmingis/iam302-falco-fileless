#!/usr/bin/env bash
# preflight.sh - kiem tra CHI DOC truoc moi dot thi nghiem:  sudo ./preflight.sh [default|custom]
# Khong sua cau hinh. Ghi bao cao vao results/preflight_<time>/preflight.txt va in PASS/FAIL.
set -u
cd "$(dirname "$0")"
EXPECT=${1:-default}
[ "$(id -u)" -eq 0 ] || { echo "can sudo"; exit 1; }
OUT=results/preflight_$(date +%Y%m%d_%H%M%S); mkdir -p "$OUT"; R="$OUT/preflight.txt"
FJ=/var/log/falco/events.json; FAIL=0
ok(){ echo "PASS  $*" | tee -a "$R"; }
bad(){ echo "FAIL  $*" | tee -a "$R"; FAIL=1; }
note(){ echo "INFO  $*" | tee -a "$R"; }

{ echo "== preflight $(date -Is) expect=$EXPECT"; uname -a; falco --version 2>/dev/null | grep -i 'falco version'
  docker version --format 'docker={{.Server.Version}}'; containerd --version; runc --version | head -1; } >> "$R" 2>&1

# ---- Falco
systemctl is-active --quiet falco-modern-bpf && ok "falco-modern-bpf active" || bad "falco-modern-bpf khong active"
if systemctl is-active --quiet falcoctl-artifact-follow; then bad "falcoctl-artifact-follow dang chay (rule co the tu cap nhat)"
else ok "falcoctl-artifact-follow da dung"; fi
LOADED=$(journalctl -u falco-modern-bpf -b -o cat --no-pager | grep -A20 'configuration files:' | tail -20)
echo "$LOADED" | grep -q '99-lab.yaml | schema validation: ok' && ok "99-lab.yaml duoc nap (journal)" || bad "khong thay 99-lab.yaml trong journal lan khoi dong nay"
# dong ho bi chinh (NTP) SAU khi Falco khoi dong -> evt.time cua Falco lech hang so (da gap: +1250 s ngay 20/10)
FM=$(systemctl show falco-modern-bpf -p ActiveEnterTimestampMonotonic --value)
SYNC=$(journalctl -b -o short-monotonic --no-pager -u systemd-timesyncd -u chrony 2>/dev/null \
  | grep -E 'synchroniz|Time has been changed|System clock wrong|clock' | sed -E 's/^\[ *([0-9]+)\.([0-9]{6})\].*/\1\2/' | sort -n | tail -1)
if [ -n "$SYNC" ] && [ "$SYNC" -gt "${FM:-0}" ]; then bad "dong ho duoc dong bo SAU khi Falco khoi dong -> sudo systemctl restart falco-modern-bpf"
else ok "khong co dong bo dong ho sau khi Falco khoi dong"; fi
RM=$(sed -n 's/^rule_matching: *//p' /etc/falco/config.d/98-lab-rule-matching.yaml 2>/dev/null)
note "rule_matching=${RM:-first (mac dinh Falco)}"
RD=$(ls -A /etc/falco/rules.d 2>/dev/null)
if [ "$EXPECT" = default ]; then [ -z "$RD" ] && ok "rules.d rong (baseline default)" || bad "rules.d co file: $RD"
else [ -n "$RD" ] && ok "rules.d: $RD" || bad "rules.d rong nhung expect=custom"; fi
echo "-- hash" >> "$R"; sha256sum /etc/falco/falco.yaml /etc/falco/falco_rules.yaml /etc/falco/falco_rules.local.yaml \
  /etc/falco/config.d/* /etc/falco/rules.d/* /etc/audit/rules.d/*.rules 2>/dev/null >> "$R"
if [ -s "$FJ" ]; then
  python3 - "$FJ" >> "$R" 2>&1 <<'EOF'
import json, re, sys
need = ["rule", "time", "priority", "output", "output_fields"]
lines = open(sys.argv[1], errors="replace").read().splitlines()[-200:]
bad = 0; frac = set()
for l in lines:
    try: j = json.loads(l)
    except ValueError: bad += 1; continue
    if any(k not in j for k in need) or "container.name" not in j["output_fields"]: bad += 1
    m = re.search(r"\.(\d+)Z$", j.get("time", "")); frac.add(len(m.group(1)) if m else -1)
print(f"events.json: {len(lines)} dong cuoi kiem, loi={bad}, so chu so phan thap phan={sorted(frac)}")
sys.exit(1 if bad or frac - {9} else 0)
EOF
  [ $? -eq 0 ] && ok "events.json dung schema (rule/time/priority/output/container.name, 9 chu so)" || bad "events.json sai schema (xem $R)"
else bad "$FJ rong hoac khong ton tai"; fi

# ---- Auditd
systemctl is-active --quiet auditd && ok "auditd active" || bad "auditd khong active"
ACT=$(auditctl -l); echo "-- auditctl -l" >> "$R"; echo "$ACT" >> "$R"
echo "-- fileless-lab.rules" >> "$R"; cat /etc/audit/rules.d/fileless-lab.rules >> "$R" 2>&1
for want in "-S memfd_create -F key=fileless_memfd" "-S execve -F key=fileless_exec" \
            "-S execveat -F key=fileless_exec" "-S ptrace -F key=fileless_ptrace"; do
  echo "$ACT" | grep -q -- "arch=b64 $want" && ok "active: b64 $want" || bad "thieu active: b64 $want"
  sed "s/ -k / -F key=/" /etc/audit/rules.d/fileless-lab.rules 2>/dev/null | grep -q -- "arch=b64 $want" \
    && ok "persistent: b64 $want" || note "persistent khong khop nguyen van '$want' (kiem tay trong $R)"
done
echo "$ACT" | grep -q 'arch=b32' && note "co rule b32" || note "chi co rule b64 (payload lab deu la ELF 64-bit; xem han che trong methodology)"
grep -q 'CONFIG_IA32_EMULATION=y' /boot/config-"$(uname -r)" 2>/dev/null && note "kernel ho tro IA32 emulation (syscall b32 kha thi)"
ST=$(auditctl -s); echo "-- auditctl -s" >> "$R"; echo "$ST" >> "$R"
L=$(echo "$ST" | awk '/^lost/{print $2}'); B=$(echo "$ST" | awk '/^backlog /{print $2}')
note "audit lost=$L backlog=$B (lost la bo dem tich luy tu khi boot; E1 do delta theo tung run)"
[ "${B:-1}" -eq 0 ] && ok "backlog=0" || bad "backlog=$B"

# ---- Docker
[ "$(docker network inspect falco-lab --format '{{.Internal}}' 2>/dev/null)" = true ] && ok "falco-lab Internal=true" || bad "falco-lab khong internal/khong ton tai"
for i in falco-lab-server falco-lab-target falco-lab-client; do
  docker image inspect "$i:latest" --format "image $i {{.Id}}" >> "$R" 2>&1 && ok "image $i" || bad "thieu image $i"; done
echo; [ $FAIL -eq 0 ] && echo "PREFLIGHT OK -> $R" || echo "PREFLIGHT CO LOI -> $R"
exit $FAIL
