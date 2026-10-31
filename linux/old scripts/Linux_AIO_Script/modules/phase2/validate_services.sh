#!/usr/bin/env bash
# modules/phase2/validate_services.sh - Validate expected services

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$SCRIPT_DIR/lib/logging.sh"
. "$SCRIPT_DIR/lib/prompts.sh"

LOG_DIR="/var/log/aio_hardening"
ROLE_FILE="$LOG_DIR/detected_role.conf"

main() {
    log "[VALIDATE] Validating services..."
    
    # Load role
    if [[ ! -f "$ROLE_FILE" ]]; then
        warn "[VALIDATE] Role not detected. Run detect_system first."
        return 0
    fi
    
    . "$ROLE_FILE"
    
    local report="$LOG_DIR/service_validation_$(date +%Y%m%d_%H%M%S).txt"
    
    echo "Service Validation Report" > "$report"
    echo "Role: $ROLE" >> "$report"
    echo "Generated: $(date)" >> "$report"
    echo "" >> "$report"
    
    # Check expected services based on role
    case "$ROLE" in
        ecomm)
            check_service "apache2" "$report" || check_service "httpd" "$report" || check_service "nginx" "$report"
            ;;
        webmail)
            check_service "postfix" "$report"
            check_service "dovecot" "$report"
            ;;
        splunk)
            check_process "splunkd" "$report"
            ;;
        *)
            log "[VALIDATE] No specific services to validate for role: $ROLE"
            ;;
    esac
    
    # Check ports
    if [[ -n "$PORTS_TCP" ]]; then
        echo "" >> "$report"
        echo "Port Check:" >> "$report"
        IFS=',' read -ra PORTS <<< "$PORTS_TCP"
        for port in "${PORTS[@]}"; do
            if ss -ltn | grep -q ":${port} "; then
                echo "  ✓ Port $port: LISTENING" >> "$report"
            else
                echo "  ✗ Port $port: NOT LISTENING" >> "$report"
            fi
        done
    fi
    
    cat "$report"
    success "[VALIDATE] Service validation complete. Report: $report"
}

check_service() {
    local service="$1"
    local report="$2"
    
    echo "" >> "$report"
    echo "Service: $service" >> "$report"
    
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        echo "  Status: RUNNING" >> "$report"
        return 0
    elif systemctl list-unit-files | grep -q "^${service}.service"; then
        echo "  Status: INSTALLED but not running" >> "$report"
        return 1
    else
        echo "  Status: NOT INSTALLED" >> "$report"
        return 1
    fi
}

check_process() {
    local proc="$1"
    local report="$2"
    
    echo "" >> "$report"
    echo "Process: $proc" >> "$report"
    
    if pgrep -x "$proc" >/dev/null; then
        echo "  Status: RUNNING" >> "$report"
        return 0
    else
        echo "  Status: NOT RUNNING" >> "$report"
        return 1
    fi
}

main "$@"
