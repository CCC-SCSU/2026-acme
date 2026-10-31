#!/usr/bin/env bash
# modules/phase2/detect_system.sh - Detect OS and Role

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$SCRIPT_DIR/lib/logging.sh"
. "$SCRIPT_DIR/lib/prompts.sh"
. "$SCRIPT_DIR/lib/detect.sh"

LOG_DIR="/var/log/aio_hardening"
ROLE_FILE="$LOG_DIR/detected_role.conf"

detect_role_auto() {
    local detected_role=""
    local detected_ports=""
    
    # Check for Apache/Nginx
    if systemctl is-active --quiet apache2 2>/dev/null || systemctl is-active --quiet httpd 2>/dev/null || systemctl is-active --quiet nginx 2>/dev/null; then
        if ss -ltn | grep -q ":80\|:443"; then
            detected_role="ecomm"
            detected_ports="80,443"
        fi
    fi
    
    # Check for mail services
    if systemctl is-active --quiet postfix 2>/dev/null || systemctl is-active --quiet dovecot 2>/dev/null; then
        detected_role="webmail"
        detected_ports="25,465,587,110,995,143,993,80,443"
    fi
    
    # Check for Splunk
    if pgrep -x splunkd >/dev/null 2>&1 || [[ -d /opt/splunk ]]; then
        detected_role="splunk"
        detected_ports="8000,8089,9997"
    fi
    
    echo "$detected_role:$detected_ports"
}

main() {
    log "[DETECT] Detecting system configuration..."
    
    # Detect OS
    local os_id os_version pkg_mgr init_sys
    os_id=$(detect_os)
    os_version=$(detect_os_version)
    pkg_mgr=$(detect_package_manager)
    init_sys=$(detect_init)
    
    log "[DETECT] OS: $os_id $os_version"
    log "[DETECT] Package Manager: $pkg_mgr"
    log "[DETECT] Init System: $init_sys"
    
    # Attempt role detection
    local auto_detect
    auto_detect=$(detect_role_auto)
    local auto_role="${auto_detect%%:*}"
    local auto_ports="${auto_detect##*:}"
    
    local final_role=""
    local final_ports=""
    
    if [[ -n "$auto_role" ]]; then
        log "[DETECT] Auto-detected role: $auto_role"
        log "[DETECT] Auto-detected ports: $auto_ports"
        echo ""
        if prompt_yes_no "Use detected role '$auto_role'?"; then
            final_role="$auto_role"
            final_ports="$auto_ports"
        fi
    fi
    
    # Manual selection if needed
    if [[ -z "$final_role" ]]; then
        echo ""
        echo "Select system role:"
        echo "  1. E-Commerce (Apache/Nginx) - ports 80,443"
        echo "  2. Webmail (Postfix/Dovecot) - ports 25,465,587,110,995,143,993,80,443"
        echo "  3. Splunk - ports 8000,8089,9997"
        echo "  4. Custom (specify ports)"
        echo "  5. Skip role-specific hardening"
        echo ""
        
        read -r -p "Selection [1-5]: " choice
        case "$choice" in
            1)
                final_role="ecomm"
                final_ports="80,443"
                ;;
            2)
                final_role="webmail"
                final_ports="25,465,587,110,995,143,993,80,443"
                ;;
            3)
                final_role="splunk"
                final_ports="8000,8089,9997"
                ;;
            4)
                final_role="custom"
                read -r -p "Enter TCP ports (comma-separated): " final_ports
                ;;
            5)
                final_role="none"
                final_ports=""
                ;;
            *)
                warn "Invalid selection. Defaulting to custom."
                final_role="custom"
                read -r -p "Enter TCP ports (comma-separated): " final_ports
                ;;
        esac
    fi
    
    # Save configuration
    cat > "$ROLE_FILE" << ROLECONF
# Auto-generated role configuration
# Generated: $(date)

# System info
OS_ID="$os_id"
OS_VERSION="$os_version"
PKG_MGR="$pkg_mgr"
INIT_SYS="$init_sys"

# Role configuration
ROLE="$final_role"
PORTS_TCP="$final_ports"
ROLECONF
    
    success "[DETECT] Role configured: $final_role"
    log "[DETECT] Ports: $final_ports"
    log "[DETECT] Configuration saved to: $ROLE_FILE"
}

main "$@"
