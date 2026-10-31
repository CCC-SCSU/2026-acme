#!/usr/bin/env bash
# Monitors for new network connections
BASELINE="/var/log/aio_hardening/baseline_network_*.txt"
REDFLAG="/var/log/redflags/new_connections.log"

ss -tulpn > /tmp/current_network.txt 2>/dev/null
latest_baseline=$(ls -t $BASELINE 2>/dev/null | head -1)

if [[ -n "$latest_baseline" ]]; then
    diff "$latest_baseline" /tmp/current_network.txt | grep "^>" | while read -r line; do
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $line" >> "$REDFLAG"
    done
fi

cp /tmp/current_network.txt "$latest_baseline" 2>/dev/null || true
rm /tmp/current_network.txt
