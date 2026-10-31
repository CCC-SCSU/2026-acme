#!/usr/bin/env bash
# Monitors for new processes
BASELINE="/var/log/aio_hardening/baseline_processes_*.txt"
REDFLAG="/var/log/redflags/new_processes.log"

latest_baseline=$(ls -t $BASELINE 2>/dev/null | head -1)
if [[ -z "$latest_baseline" ]]; then
    echo "No baseline found" >> "$REDFLAG"
    exit 0
fi

ps aux > /tmp/current_processes.txt
diff "$latest_baseline" /tmp/current_processes.txt | grep "^>" | while read -r line; do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $line" >> "$REDFLAG"
done
rm /tmp/current_processes.txt
