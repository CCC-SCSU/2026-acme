#!/usr/bin/env bash
# Monitors for user/group changes
BASELINE="/var/log/aio_hardening/baseline_users_*.txt"
REDFLAG="/var/log/redflags/user_changes.log"

awk -F: '{print $1":"$3}' /etc/passwd > /tmp/current_users.txt
latest_baseline=$(ls -t $BASELINE 2>/dev/null | head -1)

if [[ -n "$latest_baseline" ]]; then
    diff "$latest_baseline" /tmp/current_users.txt | grep "^>" | while read -r line; do
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] New user: $line" >> "$REDFLAG"
    done
fi
rm /tmp/current_users.txt
