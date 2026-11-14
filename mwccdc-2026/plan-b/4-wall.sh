#!/bin/sh
# 4-wall.sh -- the simplest safe firewall. Allows the ports you name, blocks the rest coming IN.
#   sudo sh 4-wall.sh 22 80 443     apply. Rolls back BY ITSELF in 5 minutes unless you confirm.
#   sudo sh 4-wall.sh keep          keep the rules (cancels the rollback) and save them
#   sudo sh 4-wall.sh undo          put the old rules back right now
#   sudo sh 4-wall.sh show          print the current rules
# UDP ports: prefix with u, e.g.  sudo sh 4-wall.sh 22 53 u53
# It REFUSES to change anything unless the automatic undo is armed first. You cannot lock yourself out
# for more than 5 minutes, and /root/UNDO-FIREWALL.sh always puts things back.
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
SECS=${SECS:-300}
UNDO=/root/UNDO-FIREWALL.sh
PIDF=/root/.wall-pid
have(){ command -v "$1" >/dev/null 2>&1; }
ipt_ok(){ have iptables && iptables -L -n >/dev/null 2>&1; }

case "$1" in
-h|--help|help)
  awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0;;
show)
  ipt_ok && { echo "--- iptables ---"; iptables -S; }
  have nft && { echo "--- nft ---"; nft list ruleset 2>/dev/null; }
  exit 0;;
undo)
  [ -f "$UNDO" ] || { echo "nothing to undo ($UNDO not found)"; exit 1; }
  [ -f "$PIDF" ] && { kill "$(cat $PIDF)" 2>/dev/null; rm -f "$PIDF"; }
  sh "$UNDO"; echo "old rules restored."; exit 0;;
keep)
  [ -f "$PIDF" ] || { echo "no pending rollback -- nothing to keep (did you apply rules yet?)"; exit 1; }
  kill "$(cat $PIDF)" 2>/dev/null; rm -f "$PIDF"
  echo "rollback cancelled. Rules will stay until reboot."
  if ipt_ok; then
    if   [ -d /etc/iptables ];  then iptables-save > /etc/iptables/rules.v4; echo "saved /etc/iptables/rules.v4"
    elif [ -d /etc/sysconfig ]; then iptables-save > /etc/sysconfig/iptables; echo "saved /etc/sysconfig/iptables"
    else mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4; echo "saved /etc/iptables/rules.v4"; fi
    echo "(to load at boot you still need iptables-persistent / iptables-services)"
  elif have nft; then
    nft list table inet wallb > /etc/wallb.rules 2>/dev/null && echo "saved /etc/wallb.rules"
    echo "(to load at boot: include it from /etc/nftables.conf and enable nftables.service)"
  fi
  exit 0;;
esac

[ -n "$1" ] || { echo "Usage: sudo sh $0 22 80 443   (UDP: u53)   then: sudo sh $0 keep"; exit 1; }
TCP=""; UDP=""
for p in "$@"; do
  case "$p" in
    u*) n=${p#u}; case "$n" in *[!0-9]*|'') echo "bad udp port '$p'"; exit 1;; esac
        [ "$n" -ge 1 ] && [ "$n" -le 65535 ] || { echo "udp port out of range: $p"; exit 1; }; UDP="$UDP $n";;
    *)  case "$p" in *[!0-9]*|'') echo "bad port '$p'"; exit 1;; esac
        [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || { echo "port out of range: $p"; exit 1; }; TCP="$TCP $p";;
  esac
done
case " $TCP " in *" 22 "*) ;; *) TCP="22$TCP"; echo "NOTE: adding port 22 so you keep SSH access.";; esac
echo "will allow IN  --  tcp:$TCP   udp:${UDP:- none}"

# ---------- build the undo script FIRST; refuse to continue without it ----------
if ipt_ok; then
  BK=/root/.wall-iptables.bak
  iptables-save > "$BK" 2>/dev/null || { echo "cannot save current rules; refusing to change anything"; exit 1; }
  if have ip6tables; then ip6tables-save > "$BK.v6" 2>/dev/null; fi
  cat > "$UNDO" <<EOF
#!/bin/sh
iptables-restore < $BK
[ -s $BK.v6 ] && ip6tables-restore < $BK.v6
echo "firewall restored from $BK"
EOF
elif have nft; then
  cat > "$UNDO" <<'EOF'
#!/bin/sh
nft delete table inet wallb 2>/dev/null
echo "firewall rules removed (table inet wallb deleted)"
EOF
else
  echo "no iptables and no nft on this box -- cannot set a firewall here."; exit 1
fi
chmod +x "$UNDO" || { echo "cannot write $UNDO; refusing to change anything"; exit 1; }
[ -x "$UNDO" ] || { echo "undo script not executable; refusing to change anything"; exit 1; }

# ---------- arm the automatic rollback ----------
if have setsid; then setsid sh -c "sleep $SECS; sh $UNDO >> /root/wall.log 2>&1" >/dev/null 2>&1 &
else nohup sh -c "sleep $SECS; sh $UNDO >> /root/wall.log 2>&1" >/dev/null 2>&1 & fi
RBPID=$!
sleep 1
kill -0 "$RBPID" 2>/dev/null || { echo "could not arm the automatic rollback; refusing to change anything"; exit 1; }
echo "$RBPID" > "$PIDF"
echo "automatic rollback armed (${SECS}s)."

# ---------- apply ----------
if ipt_ok; then
  iptables -P INPUT ACCEPT; iptables -F
  ok=1
  iptables -A INPUT -i lo -j ACCEPT || ok=0
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT \
    || iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT || ok=0
  iptables -A INPUT -p icmp -j ACCEPT
  iptables -A INPUT -p udp --sport 67 --dport 68 -j ACCEPT
  for p in $TCP; do iptables -A INPUT -p tcp --dport "$p" -j ACCEPT || ok=0; done
  for p in $UDP; do iptables -A INPUT -p udp --dport "$p" -j ACCEPT || ok=0; done
  if [ "$ok" = 0 ]; then
    echo "a rule failed to apply -- undoing now, nothing left half-done"; sh "$UNDO"
    kill "$RBPID" 2>/dev/null; rm -f "$PIDF"; exit 1
  fi
  iptables -P INPUT DROP          # policy goes last, so a failure above can never lock you out
  echo "applied (iptables)."
else
  R=/tmp/.wallb.$$
  { echo 'table inet wallb {'
    echo '  chain input {'
    echo '    type filter hook input priority -10; policy drop;'
    echo '    iif lo accept'
    echo '    ct state established,related accept'
    echo '    ip protocol icmp accept'
    echo '    meta l4proto ipv6-icmp accept'
    echo '    udp sport 67 udp dport 68 accept'
    printf '    tcp dport { %s } accept\n' "$(echo $TCP | tr ' ' ',')"
    [ -n "$UDP" ] && printf '    udp dport { %s } accept\n' "$(echo $UDP | tr ' ' ',')"
    echo '  }'
    echo '}'
  } > "$R"
  if ! nft -c -f "$R"; then
    echo "rule file is not valid -- nothing applied"; rm -f "$R"
    kill "$RBPID" 2>/dev/null; rm -f "$PIDF"; exit 1
  fi
  nft delete table inet wallb 2>/dev/null
  nft -f "$R" || { echo "apply failed"; sh "$UNDO"; kill "$RBPID" 2>/dev/null; rm -f "$PIDF"; rm -f "$R"; exit 1; }
  rm -f "$R"; echo "applied (nftables, table 'inet wallb'; your other rules untouched)."
fi

echo
echo "  ================================================================"
echo "   TEST EVERYTHING NOW from another window: SSH, and each service."
echo "   KEEP the rules:   sudo sh $0 keep"
echo "   UNDO right now:   sudo sh $0 undo"
if [ "$SECS" -ge 60 ]; then echo "   Do nothing and they undo themselves in $((SECS/60)) minute(s)."
     else echo "   Do nothing and they undo themselves in ${SECS}s."; fi
echo "  ================================================================"
