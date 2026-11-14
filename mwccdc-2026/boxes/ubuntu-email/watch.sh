#!/usr/bin/env bash
# watch.sh -- Ubuntu Email: keep scored services alive + monitor for changes.
#   sudo bash watch.sh           set up the watch list and start monitoring
#   sudo bash watch.sh status    what is running, what has restarted
#   sudo bash watch.sh stop      stop the background monitors
K=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
[ "$(id -u)" -eq 0 ] || { echo "run with sudo:  sudo bash watch.sh $*"; exit 1; }

case "$1" in
status)
  bash "$K/services.sh" status
  echo; echo "--- running monitors ---"
  pgrep -af 'services\.sh watch|baseline\.sh log|honeypot\.sh watch' 2>/dev/null | sed 's/^/  /' || echo "  none"
  echo; echo "--- recent tripwire hits ---"; bash "$K/honeypot.sh" alerts 10 2>/dev/null
  exit 0;;
stop)
  pkill -f 'services.sh watch' 2>/dev/null && echo "stopped service watchdog"
  pkill -f 'baseline.sh log'   2>/dev/null && echo "stopped change monitor"
  echo done; exit 0;;
esac

echo "### Build the watch list from what is actually listening"
bash "$K/services.sh" discover </dev/tty
echo
echo "*** EDIT IT NOW: delete ports that are not scored, fix any FIXME- names ***"
echo "    sudo nano /etc/ccdc/services.conf"
read -r -p "Press Enter when the list looks right... " _ </dev/tty || true
bash "$K/services.sh" check

echo; echo "### Start the watchdog (restarts a dead scored service, max 3 per 15 min)"
pkill -f "$K/services.sh watch" 2>/dev/null
setsid nohup bash "$K/services.sh" watch 30 >/dev/null 2>&1 &
echo "  running. Log: /root/ccdc-logs/services.log"

echo; echo "### Snapshot this box so you can see what red team changes"
bash "$K/baseline.sh" snap
read -r -p "Start the background change monitor too? [Y/n] " a </dev/tty
case "$a" in n|N) ;; *)
  pkill -f "$K/baseline.sh log" 2>/dev/null
  setsid nohup nice -n 19 bash "$K/baseline.sh" log 300 >/dev/null 2>&1 &
  echo "  running. Log: /root/ccdc-logs/alerts.log";; esac

cat <<EOT

RUN THIS LOOP EVERY 15 MINUTES:
  sudo bash $K/services.sh check          are my scored services up?
  sudo bash $K/baseline.sh diff           what changed?
  sudo bash $K/honeypot.sh alerts         anyone tripped a wire?
  sudo bash $K/persistence.sh             full hunt (every 30-45 min)

Watch live in a second pane:
  sudo bash $K/honeypot.sh watch

Write findings down -- incident response is 20% of the score:
  echo "\$(date '+%H:%M') <what, source IP>" >> /root/incidents.txt
EOT
