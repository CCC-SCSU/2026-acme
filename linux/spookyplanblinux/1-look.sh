#!/bin/sh
# 1-look.sh -- READ ONLY. Changes nothing, ever. Prints what is on this box and saves a copy.
#   sh 1-look.sh
# Works on bash, dash, busybox. Needs nothing but coreutils.
OUT=/root/look-$(hostname)-$(date +%m%d-%H%M).txt
h(){ echo; echo "===== $* ====="; }
{
h "WHO AM I";      hostname; cat /etc/os-release 2>/dev/null | head -3; uname -a; date
h "ADDRESSES";     (ip -br a 2>/dev/null || ifconfig -a 2>/dev/null) ; (ip r 2>/dev/null || route -n 2>/dev/null)
h "LISTENING PORTS"
if command -v ss >/dev/null 2>&1; then ss -tulpn 2>/dev/null
elif command -v netstat >/dev/null 2>&1; then netstat -tulpn 2>/dev/null
else
  echo "(no ss/netstat; reading /proc/net)"
  for f in /proc/net/tcp /proc/net/tcp6; do
    [ -r "$f" ] || continue
    awk 'function h2d(s, i,c,n,d){n=0;s=toupper(s);for(i=1;i<=length(s);i++){c=substr(s,i,1);d=index("0123456789ABCDEF",c)-1;n=n*16+d}return n}
         NR>1 && $4=="0A" {split($2,a,":"); print "LISTEN tcp", h2d(a[2])}' "$f"
  done | sort -u -k3 -n
  for f in /proc/net/udp /proc/net/udp6; do
    [ -r "$f" ] || continue
    awk 'function h2d(s, i,c,n,d){n=0;s=toupper(s);for(i=1;i<=length(s);i++){c=substr(s,i,1);d=index("0123456789ABCDEF",c)-1;n=n*16+d}return n}
         NR>1 && $4=="07" {split($2,a,":"); print "BOUND  udp", h2d(a[2])}' "$f"
  done | sort -u -k3 -n
fi
h "USERS WITH A LOGIN SHELL"; getent passwd 2>/dev/null | grep -vE '(nologin|/false|/sync|/halt|/shutdown)$' || grep -vE '(nologin|/false|/sync|/halt|/shutdown)$' /etc/passwd
h "UID 0 ACCOUNTS (should be root ONLY)"; awk -F: '$3==0{print $1}' /etc/passwd
h "EMPTY PASSWORDS (should be none)"; awk -F: '$2==""{print $1}' /etc/shadow 2>/dev/null
h "SUDO / WHEEL MEMBERS"; grep -E '^(sudo|wheel|admin):' /etc/group 2>/dev/null
h "SUDOERS (non-comment)"; cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -vE '^\s*(#|$)'
h "SSH KEYS (each one is a way in)"; find / -name 'authorized_keys*' -type f 2>/dev/null | while read -r k; do echo "--- $k"; cat "$k"; done
h "CRON"; cat /etc/crontab /etc/cron.d/* 2>/dev/null
  for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s/^/$u: /"; done
h "SYSTEMD TIMERS"; systemctl list-timers --all --no-pager 2>/dev/null | head -20
h "RUNNING SERVICES"; systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -40
h "PROCESSES"; ps -ef 2>/dev/null || ps aux 2>/dev/null
h "RECENT LOGINS"; last -n 15 2>/dev/null
h "FIREWALL NOW"
  command -v nft >/dev/null 2>&1 && { echo "--- nft"; nft list ruleset 2>/dev/null | head -40; }
  command -v iptables >/dev/null 2>&1 && { echo "--- iptables"; iptables -S 2>/dev/null; }
  command -v firewall-cmd >/dev/null 2>&1 && { echo "--- firewalld"; firewall-cmd --list-all 2>/dev/null; }
h "FILES CHANGED IN THE LAST 2 HOURS"; find /etc /usr/bin /usr/sbin /var/www /srv -xdev -type f -mmin -120 2>/dev/null | head -60
} 2>&1 | tee "$OUT"
echo
echo "Saved to $OUT   -- copy it off the box:  scp $OUT you@yourmachine:"
