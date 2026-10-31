#!/usr/bin/env bash
# modules/phase1/kernel_harden.sh - Essential kernel hardening

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=/dev/null
. "$SCRIPT_DIR/lib/logging.sh"

SYSCTL_FILE="/etc/sysctl.d/99-aio-emergency.conf"

main() {
    log "[KERNEL] Applying emergency kernel hardening..."
    
    # Create sysctl config
    cat > "$SYSCTL_FILE" << 'SYSCTL'
# AIO Hardening - Emergency Kernel Settings
# Applied during Phase 1

# IP Forwarding (disable unless router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# SYN Cookies (protect against SYN floods)
net.ipv4.tcp_syncookies = 1

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Ignore ICMP broadcast
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Enable bad error message protection
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
SYSCTL

    log "[KERNEL] Sysctl config created: $SYSCTL_FILE"
    
    # Apply immediately
    if sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1; then
        success "[KERNEL] Kernel hardening applied"
    else
        warn "[KERNEL] Some sysctl settings may have failed"
    fi
}

main "$@"
