#!/usr/bin/env bash
# Usage: baseline.sh snap | diff | watch [seconds=30] | log [seconds=120]
#   snap  record ports, processes, accounts, cron, keys, and hashes of /etc, bin dirs, web roots
#   diff  show what changed since snap;   watch = loop diff on screen
#   log   background loop appending changes to /root/ccdc-logs/alerts.log (ccdc.sh starts this at low priority)
export PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
SELF=$(readlink -f "$0"); B=/root/.baseline
key_files(){ find / \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /mnt -o -path /media -o -path /snap \) -prune -o -name 'authorized_keys*' -type f -print 2>/dev/null; }
collect(){ d=$1; mkdir -p "$d"
  ss -tuln 2>/dev/null | tail -n +2 | awk '{print $1,$5}' | sort > "$d/ports"
  # skip kernel threads (their names change constantly) and this tool's own helper processes
  ps -eo ppid,pid,user:20,comm --no-headers 2>/dev/null | awk '$1!=2 && $2!=2 {print $3,$4}' \
    | grep -vE ' (ps|sort|awk|grep|tee|sleep|find|sha256sum|diff|ss|cat|sed|cut|tail|head|tr|wc|xargs|du|df|date|env|timeout|basename|dirname|nice|ionice|mktemp|readlink|baseline.sh)$' | sort -u > "$d/procs"
  cat /etc/passwd /etc/group /etc/sudoers /etc/sudoers.d/* 2>/dev/null | sort > "$d/accounts"
  { cat /etc/crontab /etc/cron.d/* 2>/dev/null; for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s/^/$u: /"; done; } | sort > "$d/cron"
  key_files | while read -r f; do echo "$f"; cat "$f"; done > "$d/keys"
  find /etc /bin /sbin /usr/bin /usr/sbin /usr/local /var/www /srv -xdev -type f -size -20M -exec sha256sum {} + 2>/dev/null | sort -k2 > "$d/hashes"
}
case "$1" in
snap) rm -rf "$B/base"; collect "$B/base"; echo "baseline saved in $B/base";;
diff) [ -d "$B/base" ] || { echo "run snap first"; exit 1; }
      n="$B/now.$$"; collect "$n"
      for f in ports procs accounts cron keys; do
        out=$(diff "$B/base/$f" "$n/$f"); [ -n "$out" ] && { echo "### CHANGED: $f"; echo "$out" | head -40; }
      done
      # hashes: report file PATHS as new/deleted/modified instead of raw hash lines (new files first)
      if ! cmp -s "$B/base/hashes" "$n/hashes"; then
        awk '{print $2}' "$B/base/hashes" | sort > "$n/.op"; awk '{print $2}' "$n/hashes" | sort > "$n/.np"
        new_f=$(comm -13 "$n/.op" "$n/.np"); del_f=$(comm -23 "$n/.op" "$n/.np")
        mod_f=$(join -j2 -o 1.1,2.1,0 <(sort -k2 "$B/base/hashes") <(sort -k2 "$n/hashes") 2>/dev/null | awk '$1!=$2{print $3}')
        if [ -n "$new_f$del_f$mod_f" ]; then
          echo "### CHANGED: files"
          [ -n "$new_f" ] && { echo "$new_f" | sed 's/^/  NEW      /' | head -30; echo "$new_f" | wc -l | sed 's/^/  (new total: /;s/$/)/'; }
          [ -n "$mod_f" ] && echo "$mod_f" | sed 's/^/  MODIFIED /' | head -30
          [ -n "$del_f" ] && echo "$del_f" | sed 's/^/  DELETED  /' | head -15
        fi
      fi
      rm -rf "$n";;
watch) while true; do clear; date; bash "$SELF" diff; sleep "${2:-30}"; done;;
log)   mkdir -p /root/ccdc-logs
       while true; do out=$(bash "$SELF" diff); [ -n "$out" ] && { echo "=== $(date) ==="; echo "$out"; } >> /root/ccdc-logs/alerts.log; sleep "${2:-120}"; done;;
*) awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1{exit}' "$0";;
esac
