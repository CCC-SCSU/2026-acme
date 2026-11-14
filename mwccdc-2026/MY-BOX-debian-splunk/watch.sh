#!/usr/bin/env bash
# watch.sh -- MY BOX: watchdog + Splunk indexer health + change monitor.
#   sudo bash watch.sh           set everything up and start monitoring
#   sudo bash watch.sh status    what is running / what restarted / who is forwarding
#   sudo bash watch.sh stop      stop the background monitors
K=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
[ "$(id -u)" -eq 0 ] || { echo "run with sudo:  sudo bash watch.sh $*"; exit 1; }
case "$1" in
status)
  bash "$K/services.sh" status; echo
  echo "--- who is forwarding logs to me right now ---"; bash "$K/splunk.sh" indexer
  echo; echo "--- running monitors ---"
  pgrep -af 'services\.sh watch|baseline\.sh log|honeypot\.sh watch' 2>/dev/null | sed 's/^/  /' || echo "  none"
  echo; echo "--- recent tripwire hits ---"; bash "$K/honeypot.sh" alerts 10 2>/dev/null
  exit 0;;
stop)
  pkill -f 'services.sh watch' 2>/dev/null && echo "stopped service watchdog"
  pkill -f 'baseline.sh log'   2>/dev/null && echo "stopped change monitor"
  echo done; exit 0;;
esac

echo "### 1/4  Splunk health (I am the indexer -- the whole team depends on this)"
bash "$K/splunk.sh" check
echo
echo "  *** CHECK PORT 8000 ABOVE. Splunk 10 often starts with the web tier down."
echo "      If 8000 is missing:  sudo systemctl restart Splunkd   then wait 2 min."
read -r -p "  Press Enter to continue... " _ </dev/tty || true

echo; echo "### 2/4  Make sure Splunk itself is watched"
bash "$K/splunk.sh" watch

echo; echo "### 3/4  Build the scored-service watch list"
bash "$K/services.sh" discover </dev/tty
echo
echo "  *** EDIT IT: keep 8000 8089 9997, delete anything not scored ***"
echo "      sudo nano /etc/ccdc/services.conf"
read -r -p "  Press Enter when it looks right... " _ </dev/tty || true
bash "$K/services.sh" check
pkill -f "$K/services.sh watch" 2>/dev/null
setsid nohup bash "$K/services.sh" watch 30 >/dev/null 2>&1 &
echo "  watchdog running. Log: /root/ccdc-logs/services.log"

echo; echo "### 4/4  Baseline + change monitor"
bash "$K/baseline.sh" snap
pkill -f "$K/baseline.sh log" 2>/dev/null
setsid nohup nice -n 19 bash "$K/baseline.sh" log 300 >/dev/null 2>&1 &
echo "  running. Log: /root/ccdc-logs/alerts.log"

cat <<EOT

LOOP EVERY 15 MINUTES:
  sudo bash $K/services.sh check        my scored services up?
  sudo bash $K/splunk.sh indexer        is EVERY box still forwarding to me?
  sudo bash $K/baseline.sh diff         what changed?
  sudo bash $K/honeypot.sh alerts       tripwire hits?

A box missing from 'splunk.sh indexer' is not logging. Tell that box's owner --
only you can see it, and no logs means no incident reports (20% of the score).
EOT
