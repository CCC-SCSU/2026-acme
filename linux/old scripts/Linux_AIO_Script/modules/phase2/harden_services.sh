#!/usr/bin/env bash
# modules/phase2/harden_services.sh - Role-specific service hardening

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$SCRIPT_DIR/lib/logging.sh"

LOG_DIR="/var/log/aio_hardening"
ROLE_FILE="$LOG_DIR/detected_role.conf"

main() {
    log "[SERVICES] Role-specific service hardening..."
    
    # Load role
    if [[ ! -f "$ROLE_FILE" ]]; then
        warn "[SERVICES] No role detected. Skipping service hardening."
        return 0
    fi
    
    . "$ROLE_FILE"
    
    case "$ROLE" in
        ecomm)
            harden_apache
            ;;
        webmail)
            harden_postfix
            harden_dovecot
            ;;
        splunk)
            harden_splunk
            ;;
        *)
            log "[SERVICES] No specific hardening for role: $ROLE"
            ;;
    esac
    
    success "[SERVICES] Service hardening complete"
}

harden_apache() {
    log "[SERVICES] Hardening Apache/HTTP server..."
    
    # Try Apache2 (Ubuntu/Debian)
    if systemctl list-unit-files | grep -q "^apache2.service"; then
        # Disable server tokens
        if [[ -f /etc/apache2/conf-available/security.conf ]]; then
            sed -i 's/^ServerTokens.*/ServerTokens Prod/' /etc/apache2/conf-available/security.conf || true
            sed -i 's/^ServerSignature.*/ServerSignature Off/' /etc/apache2/conf-available/security.conf || true
        fi
        
        # Disable directory listing
        a2dismod autoindex 2>/dev/null || true
        a2dismod status 2>/dev/null || true
        
        log "[SERVICES] Apache hardened"
        
    # Try httpd (RHEL/Fedora)
    elif systemctl list-unit-files | grep -q "^httpd.service"; then
        if [[ -f /etc/httpd/conf/httpd.conf ]]; then
            sed -i 's/^ServerTokens.*/ServerTokens Prod/' /etc/httpd/conf/httpd.conf || true
            sed -i 's/^ServerSignature.*/ServerSignature Off/' /etc/httpd/conf/httpd.conf || true
        fi
        log "[SERVICES] Httpd hardened"
    else
        warn "[SERVICES] Apache/httpd not found"
    fi
}

harden_postfix() {
    log "[SERVICES] Hardening Postfix..."
    
    if command -v postconf >/dev/null 2>&1; then
        # Disable open relay
        postconf -e 'smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination'
        
        # Rate limiting
        postconf -e 'smtpd_client_connection_rate_limit = 10'
        postconf -e 'smtpd_error_sleep_time = 5s'
        
        # HELO required
        postconf -e 'smtpd_helo_required = yes'
        
        # Disable VRFY
        postconf -e 'disable_vrfy_command = yes'
        
        log "[SERVICES] Postfix hardened"
    else
        warn "[SERVICES] Postfix not found"
    fi
}

harden_dovecot() {
    log "[SERVICES] Hardening Dovecot..."
    
    if [[ -f /etc/dovecot/conf.d/10-auth.conf ]]; then
        # Disable plaintext auth (comment out or set to yes)
        sed -i 's/^#disable_plaintext_auth.*/disable_plaintext_auth = yes/' /etc/dovecot/conf.d/10-auth.conf || true
        log "[SERVICES] Dovecot hardened"
    else
        warn "[SERVICES] Dovecot config not found"
    fi
}

harden_splunk() {
    log "[SERVICES] Hardening Splunk..."
    
    if [[ -d /opt/splunk ]]; then
        # Password should have been changed in Phase 1 or manually
        warn "[SERVICES] Remember to change Splunk admin password manually"
        warn "[SERVICES] Command: /opt/splunk/bin/splunk edit user admin -password 'NewPass' -auth admin:changeme"
    else
        warn "[SERVICES] Splunk not found"
    fi
}

main "$@"
