#!/usr/bin/env bash
# backup.sh - run FIRST, before changing anything. No snapshots at the invitational.
# Usage: sudo bash backup.sh [dest_dir]
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root."; exit 1; }
TS=$(date +%Y%m%d-%H%M%S)
DEST=${1:-/root/.bk/$TS}
mkdir -p "$DEST"; chmod 700 "$(dirname "$DEST")" "$DEST"

paths=(/etc /var/www /root /usr/local /var/spool/cron)
[[ -d /var/lib/roundcube ]] && paths+=(/var/lib/roundcube /var/lib/dbconfig-common)
while IFS= read -r m; do paths+=("$m"); done < <(find /home -maxdepth 2 -name Maildir 2>/dev/null)

for p in "${paths[@]}"; do
  [[ -e $p ]] || continue
  out="$DEST/$(echo "$p" | sed 's#^/##; s#/#_#g').tgz"
  tar --exclude="/root/.bk" -czpf "$out" "$p" 2>/dev/null && echo "[+] $p"
done

if command -v mysqldump &>/dev/null && mysql -e 'select 1' &>/dev/null; then
  mysqldump --all-databases --single-transaction > "$DEST/all-databases.sql" && echo "[+] databases"
fi

(cd "$DEST" && sha256sum ./* > SHA256SUMS)
du -sh "$DEST"
echo "[+] Backup in $DEST"
echo "    Copy it off-box too:  scp -r $DEST sysadmin@<other-box>:~/"
echo "    Restore one file:     tar -xzpf $DEST/etc.tgz -C / etc/ssh/sshd_config"
