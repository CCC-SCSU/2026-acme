#!/usr/bin/env bash
# modules/phase2/configure_logging.sh - Configure system logging

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$SCRIPT_DIR/lib/logging.sh"

REDFLAG_DIR="/var/log/redflags"

main() {
    log "[LOGGING] Configuring enhanced logging..."
    
    # Setup log rotation for red flags
    cat > /etc/logrotate.d/aio-redflags << 'LOGROTATE'
/var/log/redflags/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
}
LOGROTATE
    
    log "[LOGGING] Log rotation configured for $REDFLAG_DIR/"
    
    # Ensure rsyslog/syslog is running
    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        log "[LOGGING] rsyslog is active"
    elif systemctl is-active --quiet syslog 2>/dev/null; then
        log "[LOGGING] syslog is active"
    else
        warn "[LOGGING] No syslog daemon detected"
    fi
    
    success "[LOGGING] Logging configuration complete"
}

main "$@"
