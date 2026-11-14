#!/usr/bin/env bash
# cleanup.sh -- end of competition. COLLECTS YOUR EVIDENCE FIRST, then removes traces.
#   sudo bash cleanup.sh collect     bundle logs/findings for your incident report (do this FIRST)
#   sudo bash cleanup.sh stop        stop the watchdog, monitor and honeypot (leave files alone)
#   sudo bash cleanup.sh creds       shred the password file only
#   sudo bash cleanup.sh all         collect, stop, then remove everything (asks each time)
#   sudo bash cleanup.sh status      what the kit has left on this box
# Order matters: 'collect' before 'all', or you delete the evidence you are scored on.
export PATH="/usr/sbin:/sbin:/usr/bin:/bin:$PATH"
case "$1" in -h|--help|help|"")
  awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0;; esac
[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo bash $0 $*"; exit 1; }
D=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ask(){ local a; read -r -p "$1 [y/N] " a || return 1; [ "$a" = y ] || [ "$a" = Y ]; }

ARTIFACTS="/root/ccdc-logs /root/.baseline /etc/ccdc /root/UNDO-FIREWALL.sh /root/fw.log /root/wall.log /root/keep.log"

do_collect(){
  OUT=/root/ccdc-evidence-$(hostname)-$(date +%m%d-%H%M)
  mkdir -p "$OUT" || return 1
  echo "Collecting into $OUT"
  cp -a /root/incidents.txt            "$OUT/" 2>/dev/null && echo "  incidents.txt (your notes)"
  cp -a /var/log/ccdc-honey.log        "$OUT/" 2>/dev/null && echo "  honeypot alerts"
  cp -a /var/log/ccdc-bait.log         "$OUT/" 2>/dev/null
  cp -a /root/ccdc-logs                "$OUT/" 2>/dev/null && echo "  kit run logs + watchdog + baseline alerts"
  for f in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages; do
    [ -r "$f" ] && cp -a "$f" "$OUT/" 2>/dev/null && echo "  $(basename $f)"; done
  journalctl --no-pager > "$OUT/journal.txt" 2>/dev/null && echo "  systemd journal"
  { echo "== accounts at end of event =="; getent passwd
    echo; echo "== UID 0 =="; awk -F: '$3==0{print $1}' /etc/passwd
    echo; echo "== listening =="; ss -tulpn 2>/dev/null
    echo; echo "== cron =="; cat /etc/crontab /etc/cron.d/* 2>/dev/null
    for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s/^/$u: /"; done
    echo; echo "== final baseline diff =="; bash "$D/baseline.sh" diff 2>/dev/null
  } > "$OUT/final-state.txt" 2>&1 && echo "  final-state.txt (accounts, ports, cron, drift)"
  tar czf "$OUT.tgz" -C /root "$(basename "$OUT")" 2>/dev/null && echo
  echo "Bundle: $OUT.tgz"
  echo "COPY IT OFF THE BOX NOW -- it is the raw material for your incident reports:"
  echo "    scp $OUT.tgz sysadmin@<your-wkst>:"
}

case "$1" in
status)
  echo "Kit artifacts on this box:"
  for p in $ARTIFACTS /root/.newcreds /var/log/ccdc-honey.log; do
    [ -e "$p" ] && printf '  present  %s\n' "$p" || printf '  gone     %s\n' "$p"; done
  ls -d /root/backup-* 2>/dev/null | sed 's/^/  present  /'
  ls -d /root/ccdc-evidence-* 2>/dev/null | sed 's/^/  present  /'
  echo
  echo "Running kit processes:"
  pgrep -af 'services\.sh (watch|monitor)|baseline\.sh log|honeypot\.sh watch' 2>/dev/null | sed 's/^/  /' || echo "  none"
  echo
  echo "Honeypot tripwires still installed:"
  grep -ls 'ccdc tripwire' /usr/local/bin/* 2>/dev/null | sed 's/^/  /' || echo "  none"
  ;;

collect) do_collect ;;

stop)
  pkill -f 'services.sh watch'   2>/dev/null && echo "stopped service watchdog"
  pkill -f 'services.sh monitor' 2>/dev/null && echo "stopped service monitor"
  pkill -f 'baseline.sh log'     2>/dev/null && echo "stopped baseline monitor"
  pkill -f 'honeypot.sh watch'   2>/dev/null && echo "stopped honeypot watcher"
  bash "$D/honeypot.sh" disarm 2>/dev/null | sed 's/^/  /'
  echo "done. Files and logs are untouched."
  ;;

creds)
  if [ -f /root/.newcreds ]; then
    ask "Shred /root/.newcreds? (make sure the passwords are on paper)" \
      && { shred -u /root/.newcreds && echo "shredded"; }
  else echo "/root/.newcreds is not present (already shredded, or never created)"; fi
  ;;

all)
  echo "=== 1. COLLECT EVIDENCE (do not skip -- incident response is 20% of the score) ==="
  ask "Collect evidence bundle now?" && do_collect
  echo
  echo "=== 2. STOP BACKGROUND PROCESSES + DISARM HONEYPOT ==="
  ask "Stop watchdogs and disarm tripwires?" && {
    pkill -f 'services.sh watch' 2>/dev/null; pkill -f 'services.sh monitor' 2>/dev/null
    pkill -f 'baseline.sh log' 2>/dev/null;   pkill -f 'honeypot.sh watch' 2>/dev/null
    bash "$D/honeypot.sh" disarm 2>/dev/null | sed 's/^/  /'; echo "  stopped"; }
  echo
  echo "=== 3. CREDENTIALS ==="
  if [ -f /root/.newcreds ]; then
    echo "  /root/.newcreds still exists. Red team recovering credentials loses points."
    ask "Shred it? (passwords should be on paper)" && shred -u /root/.newcreds && echo "  shredded"
  else echo "  no credential file present"; fi
  echo
  echo "=== 4. REMOVE KIT ARTIFACTS ==="
  echo "  This deletes logs and backups. Make sure step 1 ran and the bundle is OFF the box."
  ls -d /root/ccdc-evidence-*.tgz 2>/dev/null | sed 's/^/    bundle: /'
  if ask "Delete kit logs, baseline, backups and config?"; then
    for p in $ARTIFACTS; do [ -e "$p" ] && rm -rf "$p" && echo "  removed $p"; done
    rm -rf /root/backup-* 2>/dev/null && echo "  removed /root/backup-*"
    rm -f /root/iptables-before-*.rules 2>/dev/null
    echo "  (evidence bundles under /root/ccdc-evidence-* were KEPT)"
  fi
  echo
  echo "=== 5. WHAT WAS LEFT ALONE ON PURPOSE ==="
  echo "  /etc/ssh/sshd_config.bak.*      sshd backups -- keep until you are sure SSH is fine"
  echo "  /opt/html.BAK.*                 web root backups (if any)"
  echo "  /etc/sysctl.d/99-ccdc.conf      hardening you probably want to keep"
  echo "  Firewall rules stay in place. Remove with: bash firewall.sh undo"
  echo "  Decoy credential files from 'honeypot.sh bait' -- delete by hand if you planted them:"
  for f in /root/passwords.txt /root/.ssh-backup/id_rsa.bak /home/sysadmin/creds.txt; do
    [ -f "$f" ] && echo "      $f"; done
  ;;
*) awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1{exit}' "$0";;
esac
exit 0
