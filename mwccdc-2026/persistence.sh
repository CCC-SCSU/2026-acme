#!/usr/bin/env bash
# Read-only hunt for common red-team persistence. Changes nothing. Review output by hand.
# Usage: persistence.sh [minutes=120]   (how far back to look for modified files)
case "$1" in -h|--help|help)
  awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0;; esac
export PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
m=${1:-120}
PRUNE='-path /proc -o -path /sys -o -path /dev -o -path /run -o -path /mnt -o -path /media -o -path /snap -o -path /var/lib/docker'
sec(){ echo; echo "===== $* ====="; }
sec "UID 0 accounts";             awk -F: '$3==0{print $1}' /etc/passwd
sec "Cron (system+users)";        cat /etc/crontab /etc/cron.d/* 2>/dev/null; ls -la /etc/cron.{hourly,daily,weekly,monthly} 2>/dev/null
                                  for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s/^/$u: /"; done
sec "Systemd units changed ${m}m"; find /etc/systemd /lib/systemd /usr/lib/systemd -type f -mmin -$m 2>/dev/null | head -50
sec "rc.local / profile hooks";   cat /etc/rc.local 2>/dev/null; ls -la /etc/profile.d 2>/dev/null; grep -sH . /etc/ld.so.preload
sec "Shell rc files w/ suspicious cmds"; grep -lEs 'nc |ncat|/dev/tcp|bash -i|curl .*\|.*sh|wget .*\|.*sh|base64 -d' /home/*/.bashrc /home/*/.profile /root/.bashrc /root/.profile /etc/bash.bashrc 2>/dev/null
sec "authorized_keys";            find / \( $PRUNE \) -prune -o -name 'authorized_keys*' -type f -print 2>/dev/null | head -50 | xargs -r ls -l
sec "SUID/SGID (review for anything unusual)"
# -xdev stops at filesystem boundaries, so on a box with separate /home /var /tmp
# a single 'find / -xdev' silently skips them -- which is exactly where a SUID
# root shell gets dropped. Walk every LOCAL mount instead.
local_mounts(){
  awk '$3 !~ /^(proc|sysfs|devtmpfs|devpts|cgroup|cgroup2|securityfs|debugfs|tracefs|pstore|bpf|configfs|fusectl|mqueue|hugetlbfs|autofs|nfs|nfs4|cifs|smb3|fuse\.sshfs|squashfs|overlay|ramfs|binfmt_misc|efivarfs|rpc_pipefs|selinuxfs)$/ {print $2}' /proc/mounts \
    | sort -u | awk 'NR==1{p=$0;print;next} index($0,p"/")!=1{p=$0;print}'
}
MOUNTS=$(local_mounts); [ -n "$MOUNTS" ] || MOUNTS=/
echo "  (scanning local filesystems: $(echo $MOUNTS | tr '\n' ' '))"
for m in $MOUNTS; do
  find "$m" -xdev \( $PRUNE \) -prune -o \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null
done | sort -u | head -100
sec "Files modified ${m}m (etc,bin,web,tmp)"; find /etc /usr/bin /usr/sbin /bin /sbin /var/www /srv /tmp /dev/shm -xdev -type f -mmin -$m 2>/dev/null | head -200
sec "Executables in tmp-ish dirs"; find /tmp /var/tmp /dev/shm -xdev -type f -perm /111 2>/dev/null | head -50
sec "Possible webshells";         grep -rIlE '(eval|assert|system|passthru|shell_exec|exec)\s*\(\s*(\$_(GET|POST|REQUEST|COOKIE)|base64_decode)' /var/www /srv 2>/dev/null | head -50
sec "Listening + owning process"; ss -tulpn 2>/dev/null
sec "Odd processes (no tty, root, in /tmp etc)"
KITDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ps -eo pid,user,args | grep -E '/tmp/|/dev/shm|/var/tmp|nc |ncat|socat|bash -i' \
  | grep -v grep | grep -vF "$KITDIR" | grep -v "[ /]ps -eo" | head -50
sec "PAM / sudoers tampering";    find /etc/pam.d /etc/sudoers.d -type f -mmin -$m 2>/dev/null; grep -rE 'pam_exec|NOPASSWD' /etc/pam.d /etc/sudoers /etc/sudoers.d 2>/dev/null

exit 0
