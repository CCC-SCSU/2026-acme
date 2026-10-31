#!/usr/bin/env bash
# modules/phase1/preflight.sh - Pre-flight checks

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=/dev/null
. "$SCRIPT_DIR/lib/logging.sh"
# shellcheck source=/dev/null
. "$SCRIPT_DIR/lib/prompts.sh"

LOG_DIR="/var/log/aio_hardening"

main() {
    log "[PREFLIGHT] Starting pre-flight checks..."
    
    # Check root
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        die "Must be run as root"
    fi
    
    # Check disk space
    available_mb=$(df -BM "$LOG_DIR" 2>/dev/null | awk 'NR==2 {print $4}' | sed 's/M//' || echo "1000")
    if [[ "$available_mb" -lt 100 ]]; then
        warn "Low disk space: ${available_mb}MB available in $LOG_DIR"
    fi
    
    # Check if already ran
    if [[ -f "$LOG_DIR/.phase1_complete" ]]; then
        warn "Phase 1 marker exists. Already ran?"
        if ! prompt_yes_no "Run Phase 1 again?"; then
            die "Aborted"
        fi
        rm -f "$LOG_DIR/.phase1_complete"
    fi
    
    # System status
    log "[PREFLIGHT] System:"
    log "  Hostname: $(hostname)"
    log "  Uptime: $(uptime -p 2>/dev/null || uptime | awk '{print $3,$4}')"
    log "  Load: $(cat /proc/loadavg | awk '{print $1,$2,$3}')"
    
    success "[PREFLIGHT] Pre-flight checks passed"
}

main "$@"
