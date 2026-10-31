#!/usr/bin/env bash
# Find persistence mechanisms
echo "=== Persistence Scan ==="
echo "Generated: $(date)"
echo ""

echo "Cron jobs:"
for cronfile in /etc/crontab /etc/cron.d/* /var/spool/cron/*; do
    if [[ -f "$cronfile" ]]; then
        echo "  $cronfile"
    fi
done
echo ""

echo "Systemd timers:"
systemctl list-timers --all 2>/dev/null | head -10
echo ""

echo "RC.local:"
if [[ -f /etc/rc.local ]]; then
    echo "  /etc/rc.local exists"
    wc -l < /etc/rc.local | xargs echo "  Lines:"
fi
