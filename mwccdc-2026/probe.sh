#!/usr/bin/env bash
# probe.sh -- run this on your TEST VM. Dumps every fact the kit keys on, so you can
# confirm the scripts match reality before Saturday. READ ONLY, changes nothing.
#   sudo bash probe.sh                 print the report
#   sudo bash probe.sh > probe.txt     save it to paste back
export PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
case "$1" in -h|--help|help) sed -n '2,5p' "$0"; exit 0;; esac
[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo bash $0"; exit 1; }
sec(){ echo; echo "########## $* ##########"; }
q(){ printf '  %-34s %s\n' "$1" "$2"; }

sec "OS / PLATFORM"
. /etc/os-release 2>/dev/null
q "PRETTY_NAME" "$PRETTY_NAME"
q "kernel" "$(uname -r)"
q "init" "$( [ -d /run/systemd/system ] && echo systemd || echo 'NOT systemd' )"
q "package manager" "$(for p in apt-get dnf yum pacman; do command -v $p >/dev/null && echo $p; done | tr '\n' ' ')"

sec "FIREWALL BACKEND  (which path firewall.sh will take)"
q "firewalld active" "$(systemctl is-active firewalld 2>/dev/null || echo no)"
q "iptables present" "$(command -v iptables || echo MISSING)"
if command -v iptables >/dev/null; then
  if iptables -L -n >/dev/null 2>&1; then
    q "iptables WORKS" "yes"
    q "iptables variant" "$(iptables --version 2>/dev/null)"
  else q "iptables WORKS" "NO -- wrapper present but no kernel backend"; fi
fi
q "nft present" "$(command -v nft || echo MISSING)"
command -v nft >/dev/null && q "nft version" "$(nft --version 2>/dev/null)"
echo "  --- existing nft tables (the kit adds its own 'inet ccdc', leaves these alone):"
nft list tables 2>/dev/null | sed 's/^/      /' || echo "      (none / nft unavailable)"
echo "  --- THE TEST THAT MATTERS: does the kit's ruleset actually parse here?"
cat > /tmp/.probe.nft <<'EOT'
table inet probe_test {
  chain input {
    type filter hook input priority -10; policy drop;
    iif lo accept
    ct state established,related accept
    ct state invalid drop
    ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } accept
    meta l4proto ipv6-icmp accept
    udp sport 67 udp dport 68 accept
    tcp dport { 22,8000,8089,9997 } accept
    limit rate 5/minute log prefix "FW-DROP: "
  }
}
EOT
if command -v nft >/dev/null; then
  if nft -c -f /tmp/.probe.nft 2>/tmp/.probe.err; then
    echo "      PARSES OK -- firewall.sh nft path should work on this box"
  else
    echo "      !! FAILED TO PARSE. Send me this error:"; sed 's/^/        /' /tmp/.probe.err
  fi
fi
rm -f /tmp/.probe.nft /tmp/.probe.err

sec "SSH  (what harden.sh will touch)"
q "sshd binary" "$(command -v sshd || echo MISSING)"
q "sshd -t (config valid)" "$(command -v sshd >/dev/null && { sshd -t >/dev/null 2>&1 && echo OK || echo FAILED; } || echo 'n/a - no sshd')"
for u in ssh sshd; do systemctl cat $u.service >/dev/null 2>&1 && q "unit exists" "$u.service"; done
q "ssh.socket active" "$(systemctl is-active ssh.socket 2>/dev/null || echo no)"
q "effective Port" "$(sshd -T 2>/dev/null | awk '/^port /{print $2}' | tr '\n' ' ')"
q "PasswordAuthentication" "$(sshd -T 2>/dev/null | awk '/^passwordauthentication/{print $2}')"
q "PermitRootLogin" "$(sshd -T 2>/dev/null | awk '/^permitrootlogin/{print $2}')"

sec "SPLUNK  (what splunk.sh keys on)"
found=0
for d in /opt/splunk /opt/splunkforwarder /opt/SplunkForwarder /usr/local/splunk /usr/local/splunkforwarder; do
  [ -d "$d" ] && { found=1; q "FOUND" "$d"
    q "  binary" "$( [ -x $d/bin/splunk ] && echo $d/bin/splunk || echo 'no bin/splunk' )"
    q "  version" "$($d/bin/splunk version 2>/dev/null | head -1)"
    q "  runs as user" "$(stat -c '%U' $d 2>/dev/null)"
    echo "  --- outputs.conf (WHERE it forwards -- the red-team tamper target):"
    find "$d/etc" -name outputs.conf 2>/dev/null | while read -r f; do
      echo "      $f"; grep -vE '^\s*(#|$)' "$f" 2>/dev/null | sed 's/^/        /'; done
    echo "  --- inputs.conf (WHAT it collects):"
    find "$d/etc" -name inputs.conf 2>/dev/null | head -4 | while read -r f; do
      echo "      $f"; grep -E '^\[' "$f" 2>/dev/null | head -8 | sed 's/^/        /'; done
    echo "  --- splunkd.log present:"
    q "    " "$( [ -r $d/var/log/splunk/splunkd.log ] && echo yes || echo NO )"
  }
done
[ "$found" = 0 ] && echo "  no Splunk install found in the usual places"
echo "  --- systemd units matching splunk (THE NAME VARIES -- this is what I need):"
systemctl list-units --type=service --all --no-legend 2>/dev/null | awk '{print $1}' | grep -i splunk | sed 's/^/      /' || echo "      none"
systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -i splunk | sed 's/^/      unit-file: /'
echo "  --- init.d fallback:"; ls /etc/init.d/ 2>/dev/null | grep -i splunk | sed 's/^/      /'
echo "  --- process name (splunk.sh matches 'splunkd' exactly):"
pgrep -ax splunkd 2>/dev/null | sed 's/^/      /' || echo "      no process named exactly 'splunkd'"
ps -eo comm 2>/dev/null | grep -i splunk | sort -u | sed 's/^/      comm: /'

sec "LISTENING PORTS  (services.sh + firewall.sh parse this)"
q "ss present" "$(command -v ss || echo MISSING)"
echo "  --- raw ss -tlnp, first 12 lines (I parse the first field ending in :<digits>):"
ss -tlnp 2>/dev/null | head -12 | sed 's/^/      /'
echo "  --- EVERY tcp port, loopback included (most of these are internal, ignore them):"
ss -tln 2>/dev/null | awk 'NR>1{for(i=1;i<=NF;i++) if($i ~ /:[0-9]+$/){print $i; break}}' \
  | sed 's/.*://' | grep -E '^[0-9]+$' | sort -nu | tr '\n' ' ' | sed 's/^/      all:  /'; echo
echo "  --- what firewall.sh suggest ACTUALLY proposes (loopback filtered out):"
ss -tln 2>/dev/null | awk 'NR>1{for(i=1;i<=NF;i++) if($i ~ /:[0-9]+$/){print $i; break}}' \
  | grep -vE '^(127\.|\[::1\]|\[::ffff:127\.|::1)' | sed 's/.*://' | grep -E '^[0-9]+$' \
  | sort -nu | tr '\n' ' ' | sed 's/^/      tcp:  /'; echo
ss -uln 2>/dev/null | awk 'NR>1{for(i=1;i<=NF;i++) if($i ~ /:[0-9]+$/){print $i; break}}' \
  | grep -vE '^(127\.|\[::1\]|\[::ffff:127\.|::1)' | sed 's/.*://' | grep -E '^[0-9]+$' \
  | sort -nu | tr '\n' ' ' | sed 's/^/      udp:  /'; echo

sec "KIT SELF-TEST  (does splunk.sh read this box correctly?)"
D=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [ -f "$D/splunk.sh" ]; then bash "$D/splunk.sh" check 2>&1 | sed 's/^/  /'
else echo "  splunk.sh not next to probe.sh -- run this from inside the ccdc folder"; fi

echo
echo "########## DONE ##########"
echo "Save with:  sudo bash probe.sh > probe.txt   and send me probe.txt"
