#!/usr/bin/env bash
# Monitors critical directories for changes
REDFLAG="/var/log/redflags/file_changes.log"

find /etc /usr/local/bin -type f -mmin -5 2>/dev/null | while read -r file; do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Modified: $file" >> "$REDFLAG"
done
