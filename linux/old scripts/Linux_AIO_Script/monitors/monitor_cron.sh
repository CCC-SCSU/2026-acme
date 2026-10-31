#!/usr/bin/env bash
# Monitors for new cron jobs
REDFLAG="/var/log/redflags/cron_changes.log"

find /etc/cron* /var/spool/cron -type f -mmin -5 2>/dev/null | while read -r file; do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Cron modified: $file" >> "$REDFLAG"
done
