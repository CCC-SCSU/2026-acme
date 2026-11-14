#!/usr/bin/env bash
# harden.sh -- MY BOX: Debian Splunk, 172.20.240.20, Debian 12 + Splunk 10
#   sudo bash harden.sh          guided, asks before every change
#   sudo bash harden.sh dry      print the plan, change nothing
K=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
[ -f "$K/debian-splunk.sh" ] || { echo "Kit not found. This folder must stay inside mwccdc-2026/."; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "run with sudo:  sudo bash harden.sh $*"; exit 1; }
[ "$1" = dry ] && exec bash "$K/debian-splunk.sh" list
exec bash "$K/debian-splunk.sh"
