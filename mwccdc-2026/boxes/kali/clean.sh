#!/usr/bin/env bash
# clean.sh -- Kali: end of competition. EVIDENCE FIRST, then teardown.
#   sudo bash clean.sh           collect evidence, stop monitors, then remove (asks each step)
#   sudo bash clean.sh collect   evidence bundle only
#   sudo bash clean.sh status    what the kit left on this box
# Order matters: evidence is 20% of your score. Never delete before collecting.
K=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
[ "$(id -u)" -eq 0 ] || { echo "run with sudo:  sudo bash clean.sh $*"; exit 1; }
case "$1" in
  status)  exec bash "$K/cleanup.sh" status;;
  collect) exec bash "$K/cleanup.sh" collect;;
  *)       exec bash "$K/cleanup.sh" all;;
esac
