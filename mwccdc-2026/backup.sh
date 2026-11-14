#!/usr/bin/env bash
# Back up configs, web roots, homes, and DBs to /root/backup-<time>. Copy OFF the box afterward.
# Env: MAX_MB=500 (skip any directory bigger than this)   MIN_FREE_MB=1024 (abort if /root has less free space)
case "$1" in -h|--help|help)
  awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0;; esac
export PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
avail=$(df -Pm /root | awk 'NR==2{print $4}')
[ "${avail:-0}" -ge "${MIN_FREE_MB:-1024}" ] || { echo "Only ${avail:-?} MB free on /root (need ${MIN_FREE_MB:-1024}). Not backing up: a full disk is worse than no backup. Free space or set MIN_FREE_MB."; exit 1; }
dest=/root/backup-$(date +%Y%m%d-%H%M); mkdir -p "$dest"; chmod 700 "$dest"
tar czpf "$dest/etc.tgz" /etc 2>/dev/null
for d in /var/www /srv /home /opt /var/spool/cron /usr/local; do
  [ -d "$d" ] || continue
  mb=$(du -sm "$d" 2>/dev/null | cut -f1)
  if [ "${mb:-0}" -gt "${MAX_MB:-500}" ] || [ "${mb:-0}" -gt $((avail / 2)) ]; then
    echo "SKIPPING $d (${mb} MB; limit ${MAX_MB:-500} MB, free ${avail} MB; rerun with MAX_MB=<n> to include)"; continue; fi
  tar czpf "$dest/$(echo "$d" | tr / _).tgz" "$d" 2>/dev/null
done
command -v mysqldump  >/dev/null && mysqldump --all-databases --single-transaction --quick --skip-lock-tables > "$dest/mysql-all.sql" 2>/dev/null
command -v pg_dumpall >/dev/null && su -s /bin/sh postgres -c pg_dumpall > "$dest/pg-all.sql" 2>/dev/null
find "$dest" -name '*.sql' -size 0 -delete
(cd "$dest" && sha256sum * > SHA256SUMS)
echo "Backup in $dest"; ls -lh "$dest"
echo "REMINDER: copy this off the host (scp) so red team can't delete it."
