#!/usr/bin/env bash
# modules/phase2/detect_persistence.sh - Scan for persistence mechanisms

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$SCRIPT_DIR/lib/logging.sh"
. "$SCRIPT_DIR/lib/prompts.sh"

LOG_DIR="/var/log/aio_hardening"

main() {
    log "[PERSISTENCE] Scanning for persistence mechanisms..."
    
    local report="$LOG_DIR/persistence_scan_$(date +%Y%m%d_%H%M%S).txt"
    
    echo "Persistence Detection Report" > "$report"
    echo "Generated: $(date)" >> "$report"
    echo "" >> "$report"
    
    # Scan cron jobs
    log "[PERSISTENCE] Scanning cron jobs..."
    echo "=== CRON JOBS ===" >> "$report"
    
    # System crontabs
    for cronfile in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
        if [[ -f "$cronfile" ]]; then
            if grep -qE "nc|bash -i|curl.*sh|wget.*sh|python.*socket|perl.*socket" "$cronfile" 2>/dev/null; then
                echo "SUSPICIOUS: $cronfile" >> "$report"
                grep -n "nc\|bash -i\|curl.*sh" "$cronfile" >> "$report" 2>/dev/null || true
            fi
        fi
    done
    
    # User crontabs
    for user_cron in /var/spool/cron/crontabs/* /var/spool/cron/*; do
        if [[ -f "$user_cron" ]]; then
            if grep -qE "nc|bash -i|curl.*sh" "$user_cron" 2>/dev/null; then
                echo "SUSPICIOUS USER CRON: $user_cron" >> "$report"
            fi
        fi
    done
    
    # Systemd timers
    if command -v systemctl >/dev/null 2>&1; then
        log "[PERSISTENCE] Scanning systemd timers..."
        echo "" >> "$report"
        echo "=== SYSTEMD TIMERS ===" >> "$report"
        systemctl list-timers --all >> "$report" 2>/dev/null || true
    fi
    
    # Check rc.local
    log "[PERSISTENCE] Checking /etc/rc.local..."
    if [[ -f /etc/rc.local ]]; then
        echo "" >> "$report"
        echo "=== RC.LOCAL ===" >> "$report"
        cat /etc/rc.local >> "$report"
    fi
    
    # Check profile.d
    log "[PERSISTENCE] Scanning /etc/profile.d/..."
    echo "" >> "$report"
    echo "=== PROFILE.D SCRIPTS ===" >> "$report"
    ls -la /etc/profile.d/ >> "$report" 2>/dev/null || true
    
    # Check for hidden files in unusual places
    log "[PERSISTENCE] Scanning for hidden files..."
    echo "" >> "$report"
    echo "=== HIDDEN FILES ===" >> "$report"
    find /tmp /var/tmp /dev/shm -name ".*" -type f 2>/dev/null >> "$report" || true
    
    success "[PERSISTENCE] Persistence scan complete. Report: $report"
    
    # Review with user
    echo ""
    if prompt_yes_no "Review persistence report now?"; then
        less "$report"
    fi
}

main "$@"
