#!/usr/bin/env bash
# clean.sh -- MY BOX: end of competition. EVIDENCE FIRST, then teardown.
#   sudo bash clean.sh           collect, stop, remove (asks each step)
#   sudo bash clean.sh collect   evidence bundle only
#   sudo bash clean.sh status    what the kit left behind
# YOUR BOX HOLDS THE LOGS FOR THE WHOLE NETWORK. Collect before you delete.
K=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
[ "$(id -u)" -eq 0 ] || { echo "run with sudo:  sudo bash clean.sh $*"; exit 1; }
case "$1" in
  status)  exec bash "$K/cleanup.sh" status;;
  collect) exec bash "$K/cleanup.sh" collect;;
esac
echo "You are the Splunk indexer: your evidence bundle is the team's incident-report"
echo "material. Make sure it is copied OFF this box before anything is deleted."
echo
exec bash "$K/cleanup.sh" all
