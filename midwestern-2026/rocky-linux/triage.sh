#!/usr/bin/env bash
# triage.sh - read-only sweep for persistence, backdoors and misconfig.
# Changes nothing. Saves a report you can diff later and quote in incident reports.
# Usage: sudo bash triage.sh            (full)
#        sudo bash triage.sh --quick    (skips package verification)
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root."; exit 1; }
QUICK=${1:-}
OUT=/root/triage-$(hostname)-$(date +%H%M).txt
exec > >(tee "$OUT") 2>&1
h() { printf '\n===== %s =====\n' "$*"; }
RPM=0; command -v rpm &>/dev/null && command -v dnf &>/dev/null && RPM=1

h "HOST"; hostname; date; ip -4 -br a; ip route | head -3
h "LISTENING PORTS"; ss -tulpn
h "ESTABLISHED"; ss -tnp state established
h "UID 0 ACCOUNTS (should be root only)"; awk -F: '$3==0' /etc/passwd
h "ACCOUNTS WITH A LOGIN SHELL"; awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1, $3, $6, $7}' /etc/passwd
h "EMPTY PASSWORDS"; awk -F: '$2==""{print $1}' /etc/shadow
h "ADMIN GROUPS"; getent group wheel sudo adm
h "SUDOERS"; grep -HvE '^\s*(#|$)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null
h "AUTHORIZED KEYS"
find / -xdev \( -name authorized_keys -o -name authorized_keys2 \) 2>/dev/null | while read -r f; do
  echo "--- $f"; lsattr "$f" 2>/dev/null; cat "$f"; done
h "SSHD EFFECTIVE CONFIG"
sshd -T 2>/dev/null | grep -Ei '^(port|permitrootlogin|passwordauthentication|permitemptypasswords|pubkeyauthentication|authorizedkeysfile|maxauthtries|x11forwarding) '
ls -la /etc/ssh/sshd_config.d/ 2>/dev/null
h "CRON"
cat /etc/crontab 2>/dev/null | grep -vE '^\s*(#|$)'
for f in /etc/cron.d/*; do echo "--- $f"; grep -vE '^\s*(#|$)' "$f"; done
ls -la /etc/cron.hourly /etc/cron.daily 2>/dev/null
for u in $(cut -d: -f1 /etc/passwd); do c=$(crontab -l -u "$u" 2>/dev/null | grep -vE '^\s*(#|$)'); [[ -n $c ]] && echo "--- user $u" && echo "$c"; done
h "SYSTEMD TIMERS"; systemctl list-timers --all --no-pager | head -30
h "CUSTOM UNITS in /etc/systemd/system"
find /etc/systemd/system -maxdepth 1 -type f \( -name '*.service' -o -name '*.timer' \) | while read -r f; do
  echo "--- $f"; grep -E '^(ExecStart|Description)' "$f"; done
h "RUNNING SERVICES"; systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}'
h "PROCESSES"; ps -eo pid,ppid,user,etime,cmd --sort=user | grep -v '\[.*\]$'
h "SUID/SGID NOT OWNED BY A PACKAGE"
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while read -r f; do
  if [[ $RPM == 1 ]]; then rpm -qf "$f" &>/dev/null || echo "UNPACKAGED: $f"
  else dpkg -S "$f" &>/dev/null || echo "UNPACKAGED: $f"; fi
done
echo "(all SUID - compare with a clean box):"; find / -xdev -type f -perm -4000 2>/dev/null
h "HIDDEN / EXEC FILES IN TEMP DIRS"; find /tmp /var/tmp /dev/shm -xdev \( -name '.*' -o -perm -u+x \) -type f -ls 2>/dev/null
h "/usr/local CONTENTS"; find /usr/local/bin /usr/local/sbin -type f -ls 2>/dev/null
h "LOGIN HOOKS"; ls -la /etc/profile.d/; grep -HnE 'curl|wget|nc |bash -i|/dev/tcp|alias ' /root/.bashrc /root/.profile /home/*/.bashrc /etc/bash.bashrc /etc/profile 2>/dev/null
[[ -s /etc/ld.so.preload ]] && { h "LD_PRELOAD (!!)"; cat /etc/ld.so.preload; }
h "FILE PERMS"; ls -l /etc/passwd /etc/shadow /etc/sudoers
h "WEB ROOT: suspicious PHP"
grep -RIlE 'eval\(|base64_decode|shell_exec|passthru|system\(|popen|proc_open|assert\(|phpinfo' /var/www 2>/dev/null
find /var/www -name '.*' -type f 2>/dev/null
h "FIREWALL"
if command -v firewall-cmd &>/dev/null; then firewall-cmd --list-all; fi
if command -v ufw &>/dev/null; then ufw status verbose; fi
h "MAC (SELinux/AppArmor)"; getenforce 2>/dev/null; aa-status --enabled 2>/dev/null && echo "AppArmor on"

if command -v postconf &>/dev/null; then
  h "POSTFIX (non-default)"; postconf -n
  h "MAIL FORWARDS"; grep -vE '^\s*(#|$)' /etc/aliases; find /home /root -maxdepth 2 -name .forward -exec sh -c 'echo "--- $1"; cat "$1"' _ {} \;
  h "MAIL QUEUE"; mailq | tail -5
  h "DOVECOT"; doveconf -n 2>/dev/null | grep -vE '^#'
fi
if command -v mysql &>/dev/null && mysql -e 'select 1' &>/dev/null; then
  h "DB USERS"; mysql -e "SELECT user,host FROM mysql.user"
  h "DB BIND"; grep -RH bind-address /etc/my.cnf /etc/my.cnf.d /etc/mysql 2>/dev/null
fi
h "RECENT LOGINS"; last -n 15 2>/dev/null; lastb -n 10 2>/dev/null
if [[ $QUICK != --quick ]]; then
  h "PACKAGE FILES CHANGED (5=hash, M=mode)"
  if [[ $RPM == 1 ]]; then rpm -Va 2>/dev/null | grep -E '^(..5|.M)' | head -60
  else dpkg --verify 2>/dev/null | head -60; fi
fi
echo; echo "[+] Report saved: $OUT"
