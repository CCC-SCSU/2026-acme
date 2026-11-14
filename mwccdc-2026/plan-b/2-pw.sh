#!/bin/sh
# 2-pw.sh -- change ONE password at a time. Deliberately not a mass tool: one at a time cannot surprise you.
#   sh 2-pw.sh              list accounts that can log in
#   sh 2-pw.sh USER         give USER a new random password and SHOW it once
#   sh 2-pw.sh USER mypass  set a password you choose
# MWCCDC: submit every change through the scoring engine (https://quotient.ccdc.events), not a ticket.
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
if [ -z "$1" ]; then
  echo "Accounts with a login shell:"
  getent passwd 2>/dev/null | grep -vE '(nologin|/false|/sync|/halt|/shutdown)$' | cut -d: -f1,3,7 | tr ':' ' ' | sed 's/^/  /'
  echo
  echo "Usage: sudo sh 2-pw.sh <user>"
  echo "WARNING: do not change a scoring account without submitting it to the scoring engine."
  exit 0
fi
U=$1
id "$U" >/dev/null 2>&1 || { echo "no such user: $U"; exit 1; }
if [ -n "$2" ]; then P=$2
else
  # no look-alike characters, easy to copy onto paper
  P=$(tr -dc 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789' < /dev/urandom 2>/dev/null | head -c 14)
  [ -n "$P" ] || P=$(date +%s | sha256sum | head -c 14)
fi
[ ${#P} -ge 8 ] || { echo "password too short, aborting"; exit 1; }
echo
echo "  ============================================"
printf '   USER: %s\n   PASS: %s\n' "$U" "$P"
echo "  ============================================"
echo "  WRITE THIS ON PAPER NOW."
echo
printf 'Change it? [y/N] '; read ANS
case "$ANS" in y|Y) ;; *) echo "not changed"; exit 0;; esac
if echo "$U:$P" | chpasswd 2>/dev/null; then
  echo "changed. Submit it to the scoring engine if this is a scored account."
else
  echo "chpasswd failed -- password NOT changed. Try: passwd $U"
fi
