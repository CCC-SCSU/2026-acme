#!/bin/sh
# 5-hunt.sh -- READ ONLY. Looks for the usual red-team footholds. Changes nothing.
#   sh 5-hunt.sh
h(){ echo; echo "===== $* ====="; }
h "EXTRA UID 0 ACCOUNTS (anything but 'root' is bad)"; awk -F: '$3==0{print $1}' /etc/passwd
h "ACCOUNTS WITH NO PASSWORD"; awk -F: '$2==""{print $1}' /etc/shadow 2>/dev/null
h "PASSWORDLESS SUDO"; grep -r NOPASSWD /etc/sudoers /etc/sudoers.d 2>/dev/null
h "SSH KEYS"; find / -name 'authorized_keys*' -type f 2>/dev/null | while read -r k; do echo "--- $k"; cat "$k"; done
h "CRON JOBS"; cat /etc/crontab /etc/cron.d/* 2>/dev/null
  for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s/^/$u: /"; done
h "LD_PRELOAD ROOTKIT HOOK (should be empty)"; cat /etc/ld.so.preload 2>/dev/null
h "STARTUP HOOKS"; cat /etc/rc.local 2>/dev/null; ls -la /etc/profile.d 2>/dev/null
h "SHELL STARTUP FILES WITH NETWORK COMMANDS"
  grep -lEs 'nc |ncat|/dev/tcp|bash -i|curl .*\| *sh|wget .*\| *sh|base64 -d' /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile /etc/bash.bashrc 2>/dev/null
h "EXECUTABLES IN TEMP DIRS (very suspicious)"; find /tmp /var/tmp /dev/shm -type f -perm -111 2>/dev/null | head -30
h "PROCESSES RUNNING FROM TEMP DIRS"; ps -ef 2>/dev/null | grep -E '/tmp/|/dev/shm|/var/tmp' | grep -v grep
h "REVERSE-SHELL-LOOKING PROCESSES"; ps -ef 2>/dev/null | grep -E ' nc | ncat | socat |bash -i|sh -i' | grep -v grep
h "POSSIBLE WEB SHELLS"
  grep -rIlE '(eval|system|passthru|shell_exec|exec)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)' /var/www /srv /usr/share/nginx 2>/dev/null | head -20
h "SUID BINARIES (compare against a clean box if you can)"; find / -xdev -perm -4000 -type f 2>/dev/null | head -40
h "RECENTLY MODIFIED SYSTEM FILES (2h)"; find /etc /usr/bin /usr/sbin /bin /sbin -xdev -type f -mmin -120 2>/dev/null | head -40
h "NEW/ODD SYSTEMD UNITS (2h)"; find /etc/systemd /lib/systemd /usr/lib/systemd -type f -mmin -120 2>/dev/null | head -20
echo
echo "Nothing above was changed. Investigate anything that looks wrong before you delete it."
