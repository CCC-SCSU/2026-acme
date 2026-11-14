#!/usr/bin/env bash
# Quick host inventory -> ./inventory-<host>-<time>.txt  (run as root)
case "$1" in -h|--help|help)
  awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0;; esac
out="inventory-$(hostname)-$(date +%Y%m%d-%H%M).txt"
sec(){ echo; echo "===== $* ====="; }
{
sec OS;            cat /etc/os-release; uname -a
sec ADDRESSES;     ip -br a; ip r
sec LISTENING;     ss -tulpn
sec ESTABLISHED;   ss -tnp state established
sec RUNNING-SVCS;  systemctl list-units --type=service --state=running --no-pager 2>/dev/null
sec LOGIN-USERS;   getent passwd | awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)$/'
sec UID0;          awk -F: '$3==0{print $1}' /etc/passwd
sec SUDOERS;       grep -rhv '^\s*#' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -v '^\s*$'
sec LOGGED-IN;     w
sec CRON;          for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s/^/$u: /"; done
                   ls -la /etc/cron* 2>/dev/null
sec TIMERS;        systemctl list-timers --all --no-pager 2>/dev/null
sec WEB-DB-HINTS;  for s in apache2 httpd nginx mysql mariadb postgresql ssh sshd vsftpd proftpd smbd named bind9 dovecot postfix; do
                     systemctl is-active "$s" 2>/dev/null | sed "s/^/$s: /"; done
sec FIREWALL;      iptables -S 2>/dev/null; nft list ruleset 2>/dev/null | head -50; ufw status 2>/dev/null
} > "$out" 2>&1
echo "Wrote $out"

exit 0
