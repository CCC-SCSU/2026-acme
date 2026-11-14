#!/usr/bin/env bash
# Default-deny INBOUND firewall with automatic rollback.
# Backends, picked automatically: firewalld > iptables > nftables (Debian 13 / Arch often have only nft).
# Usage:
#   ALLOW_TCP="22 80 443" [ALLOW_UDP="53"] [MGMT=cidr] [SSH_PORT=22] [FORWARD=ACCEPT] [ROLLBACK_SECS=300] [DRY=1] ./firewall.sh
#   ./firewall.sh suggest   print what this box is LISTENING on (no changes)
#   ./firewall.sh save      persist current rules (run AFTER you kill the rollback timer)
#   ./firewall.sh undo      remove this script's rules right now
# FORWARD_DROP=1 also blocks forwarded traffic (nft backend). Leave it off on Docker/K8S boxes.
# DRY=1 prints every command without running it.
# MWCCDC 2026: rule 9 requires public services reachable from ALL source IPs. Source-IP filtering
# "may incur a penalty when detected" and knife-edge scoring-engine-only access is PROHIBITED.
# MGMT is therefore refused unless you pass ALLOW_SOURCE_FILTER=1, which you should only do to
# block a specific attacking IP -- never to allow-list the scoring engine.
export PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
DRY=${DRY:-0}
x(){ if [ "$DRY" = 1 ]; then echo "  [dry] $*"; else "$@"; fi; }
fwd_active(){ systemctl is-active --quiet firewalld 2>/dev/null; }
have(){ command -v "$1" >/dev/null 2>&1; }
# iptables counts only if it actually runs (a bare wrapper with no kernel backend fails here)
ipt_ok(){ have iptables && iptables -L -n >/dev/null 2>&1; }

case "$1" in -h|--help|help)
  awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0;; esac

if [ "$1" = suggest ]; then
  for proto in tcp udp; do
    ports=$(ss -${proto:0:1}ln 2>/dev/null | awk 'NR>1{for(i=1;i<=NF;i++) if($i ~ /:[0-9]+$/){print $i; break}}' | grep -vE '^(127\.|\[::1\]|\[::ffff:127\.|::1)' | sed 's/.*://' | grep -E '^[0-9]+$' | sort -nu | tr '\n' ' ')
    echo "$proto listening on non-loopback: ${ports:-none}"
  done
  echo; echo "Remove anything that is not a scored service, then:"
  echo "  ALLOW_TCP=\"<tcp>\" ALLOW_UDP=\"<udp>\" $0"
  exit 0
fi

if [ "$1" = undo ]; then
  if have nft && nft list table inet ccdc >/dev/null 2>&1; then nft delete table inet ccdc && echo "removed nft table inet ccdc"; fi
  ls -t /root/iptables-before-*.rules 2>/dev/null | head -1 | while read -r f; do
    iptables-restore < "$f" && echo "restored $f"; done
  fwd_active && firewall-cmd --reload && echo "firewalld reloaded"
  exit 0
fi

if [ "$1" = save ]; then
  if fwd_active; then firewall-cmd --runtime-to-permanent && echo "saved (firewalld)"
  elif have nft && nft list table inet ccdc >/dev/null 2>&1; then
    mkdir -p /etc/nftables.d
    nft list table inet ccdc > /etc/ccdc-nft.rules
    echo "saved to /etc/ccdc-nft.rules"
    echo "To load at boot: add 'include \"/etc/ccdc-nft.rules\"' to /etc/nftables.conf and enable nftables.service"
  elif [ -d /etc/sysconfig ]; then
    iptables-save > /etc/sysconfig/iptables; ip6tables-save > /etc/sysconfig/ip6tables 2>/dev/null
    echo "saved to /etc/sysconfig (needs iptables-services enabled to load at boot)"
  elif have netfilter-persistent; then netfilter-persistent save
  else mkdir -p /etc/iptables; iptables-save > /etc/iptables/rules.v4
       echo "saved to /etc/iptables/rules.v4 (needs iptables-persistent to load at boot)"; fi
  exit 0
fi

[ -n "$ALLOW_TCP$ALLOW_UDP" ] || { echo "Set ALLOW_TCP/ALLOW_UDP (see header). Try: $0 suggest"; exit 1; }
SSH=${SSH_PORT:-22}; ALLOW_TCP="$SSH $ALLOW_TCP"; RB=${ROLLBACK_SECS:-300}
# de-duplicate and validate
ALLOW_TCP=$(echo $ALLOW_TCP | tr ' ' '\n' | awk 'NF && !s[$0]++' | tr '\n' ' ')
ALLOW_UDP=$(echo $ALLOW_UDP | tr ' ' '\n' | awk 'NF && !s[$0]++' | tr '\n' ' ')
for p in $ALLOW_TCP $ALLOW_UDP; do
  [[ $p =~ ^[0-9]+$ ]] && [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || { echo "bad port '$p' (1-65535, space-separated)"; exit 1; }; done
if [ -n "$MGMT" ] && [ "$ALLOW_SOURCE_FILTER" != 1 ]; then
  echo "REFUSING: MGMT restricts SSH to one source range. MWCCDC rule 9 requires public services"
  echo "          to be reachable from ALL source IPs; filtering may incur a penalty and"
  echo "          scoring-engine-only 'knife edge' access is prohibited."
  echo "          If you are blocking a specific attacking IP and know what you are doing:"
  echo "              ALLOW_SOURCE_FILTER=1 MGMT=... $0 ..."
  exit 1
fi
[ -z "$MGMT" ] || [[ $MGMT =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]] || { echo "bad MGMT '$MGMT' (want a CIDR like 172.20.240.0/24)"; exit 1; }
rm -f /run/ccdc-fw.pid
echo "Allowing TCP: $ALLOW_TCP"; echo "Allowing UDP: ${ALLOW_UDP:-none}"; [ "$DRY" = 1 ] && echo "** DRY RUN -- nothing will be changed **"

# ============================== firewalld ==============================
if fwd_active; then
  echo "backend: firewalld"
  zones=$(firewall-cmd --get-active-zones 2>/dev/null | grep -v '^[[:space:]]')
  [ -n "$zones" ] || zones=$(firewall-cmd --get-default-zone)
  if [ "$DRY" != 1 ]; then
    setsid bash -c "sleep $RB; firewall-cmd --reload" >/dev/null 2>&1 &
    pid=$!; echo $pid > /run/ccdc-fw.pid
    echo "Runtime-only changes; auto-revert in ${RB}s. Test from a SECOND session, then: kill $pid && $0 save"
  fi
  for zone in $zones; do
    case $zone in trusted|docker|libvirt*) echo "skipping zone $zone"; continue;; esac
    for s in $(firewall-cmd --zone=$zone --list-services 2>/dev/null); do x firewall-cmd -q --zone=$zone --remove-service=$s; done
    for p in $(firewall-cmd --zone=$zone --list-ports 2>/dev/null);    do x firewall-cmd -q --zone=$zone --remove-port=$p; done
    firewall-cmd --zone=$zone --list-rich-rules 2>/dev/null | while read -r r; do [ -n "$r" ] && x firewall-cmd -q --zone=$zone --remove-rich-rule="$r"; done
    for p in $ALLOW_TCP; do
      if [ "$p" = "$SSH" ] && [ -n "$MGMT" ]; then
        x firewall-cmd -q --zone=$zone --add-rich-rule="rule family=ipv4 source address=$MGMT port port=$p protocol=tcp accept"
      else x firewall-cmd -q --zone=$zone --add-port=$p/tcp; fi
    done
    for p in $ALLOW_UDP; do x firewall-cmd -q --zone=$zone --add-port=$p/udp; done
    [ "$DRY" != 1 ] && firewall-cmd --zone=$zone --list-all
  done
  exit 0
fi

# ============================== iptables ==============================
if ipt_ok; then
  echo "backend: iptables"
  save=/root/iptables-before-$(date +%H%M%S).rules; save6=$save.v6
  if [ "$DRY" != 1 ]; then
    iptables-save > "$save" || { echo "iptables-save failed; not touching the firewall"; exit 1; }
    have ip6tables-save && ip6tables-save > "$save6" 2>/dev/null
    setsid bash -c "sleep $RB; iptables-restore < $save; [ -s $save6 ] && ip6tables-restore < $save6; echo 'firewall rolled back' >> /root/fw.log" >/dev/null 2>&1 &
    pid=$!; echo $pid > /run/ccdc-fw.pid
    echo "Auto-rollback in ${RB}s. Test from a SECOND session, then: kill $pid && $0 save"
  fi
  undo(){ iptables-restore < "$save"; [ -s "$save6" ] && ip6tables-restore < "$save6"; }
  must(){ if [ "$DRY" = 1 ]; then echo "  [dry] $*"; return 0; fi
          "$@" || { echo "FAILED: $*  -- restoring previous rules"; undo; kill $pid 2>/dev/null; rm -f /run/ccdc-fw.pid; exit 1; }; }
  x iptables -P INPUT ACCEPT; x iptables -F; x iptables -X
  must iptables -A INPUT -i lo -j ACCEPT
  must iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  x iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT   # Ping is SCORED (rule 12: maintain ICMP)
  x iptables -A INPUT -p udp --sport 67 --dport 68 -j ACCEPT
  for p in $ALLOW_TCP; do
    if [ "$p" = "$SSH" ] && [ -n "$MGMT" ]; then must iptables -A INPUT -p tcp --dport "$p" -s "$MGMT" -j ACCEPT
    else must iptables -A INPUT -p tcp --dport "$p" -j ACCEPT; fi
  done
  for p in $ALLOW_UDP; do must iptables -A INPUT -p udp --dport "$p" -j ACCEPT; done
  x iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "FW-DROP: "
  x iptables -P INPUT DROP; x iptables -P FORWARD "${FORWARD:-DROP}"; x iptables -P OUTPUT ACCEPT
  if have ip6tables && ip6tables -L -n >/dev/null 2>&1; then
    x ip6tables -P INPUT ACCEPT; x ip6tables -F
    if [ "$DRY" = 1 ] || { ip6tables -A INPUT -i lo -j ACCEPT && ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT && ip6tables -A INPUT -p ipv6-icmp -j ACCEPT; }; then
      for p in $ALLOW_TCP; do x ip6tables -A INPUT -p tcp --dport "$p" -j ACCEPT; done
      for p in $ALLOW_UDP; do x ip6tables -A INPUT -p udp --dport "$p" -j ACCEPT; done
      x ip6tables -P INPUT DROP; x ip6tables -P FORWARD DROP
    else echo "ip6tables rules failed; leaving IPv6 policy open"; fi
  fi
  [ "$DRY" != 1 ] && { iptables -S; echo; echo "-- nat/mangle (look for REDIRECT/DNAT you did not add):"; iptables -t nat -S 2>/dev/null; }
  exit 0
fi

# ============================== nftables ==============================
have nft || { echo "no firewalld, no working iptables, no nft. Install one (Debian: nftables; Arch: pacman -S nftables)."; exit 1; }
echo "backend: nftables (adding our own table 'inet ccdc'; other tables are left alone)"
tcpset=$(echo $ALLOW_TCP | tr ' ' ','); udpset=$(echo $ALLOW_UDP | tr ' ' ',')
rules=/run/ccdc-nft.rules
{
  echo 'table inet ccdc {'
  echo '  chain input {'
  echo '    type filter hook input priority -10; policy drop;'
  echo '    iif lo accept'
  echo '    ct state established,related accept'
  echo '    ct state invalid drop'
  echo '    ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } accept'
  echo '    meta l4proto ipv6-icmp accept'
  echo '    udp sport 67 udp dport 68 accept'
  echo '    udp sport 547 udp dport 546 accept'
  if [ -n "$MGMT" ]; then
    echo "    ip saddr $MGMT tcp dport $SSH accept"
    rest=$(echo $ALLOW_TCP | tr ' ' '\n' | grep -vx "$SSH" | tr '\n' ',' | sed 's/,$//')
    [ -n "$rest" ] && echo "    tcp dport { $rest } accept"
  else
    echo "    tcp dport { $tcpset } accept"
  fi
  [ -n "$udpset" ] && echo "    udp dport { $udpset } accept"
  echo '    limit rate 5/minute log prefix "FW-DROP: "'
  echo '  }'
  if [ "$FORWARD_DROP" = 1 ]; then
    echo '  chain forward { type filter hook forward priority -10; policy drop; ct state established,related accept; }'
  fi
  echo '}'
} > "$rules"
echo "--- ruleset ---"; cat "$rules"; echo "---------------"
[ "$DRY" = 1 ] && { nft -c -f "$rules" && echo "ruleset parses OK (dry run, nothing applied)"; exit 0; }
nft -c -f "$rules" || { echo "ruleset failed to parse; nothing applied"; exit 1; }
nft list table inet ccdc >/dev/null 2>&1 && nft delete table inet ccdc
setsid bash -c "sleep $RB; nft delete table inet ccdc 2>/dev/null; echo 'firewall rolled back' >> /root/fw.log" >/dev/null 2>&1 &
pid=$!; echo $pid > /run/ccdc-fw.pid
echo "Auto-rollback in ${RB}s (deletes table inet ccdc). Test from a SECOND session, then: kill $pid && $0 save"
nft -f "$rules" || { echo "apply failed; removing our table"; nft delete table inet ccdc 2>/dev/null; kill $pid 2>/dev/null; exit 1; }
nft list table inet ccdc
