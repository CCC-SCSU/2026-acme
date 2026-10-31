#!/usr/bin/env bash
# modules/phase2/harden_network.sh - Comprehensive network hardening

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$SCRIPT_DIR/lib/logging.sh"
. "$SCRIPT_DIR/lib/prompts.sh"

SYSCTL_FILE="/etc/sysctl.d/99-aio-hardening.conf"

main() {
    log "[NETWORK] Comprehensive network hardening..."
    
    # Create comprehensive sysctl config
    cat > "$SYSCTL_FILE" << 'SYSCTL'
# AIO Hardening - Comprehensive Network Settings
# Applied during Phase 2

# IP Forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# SYN Cookies
net.ipv4.tcp_syncookies = 1

# Source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# ICMP
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# TCP hardening
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_synack_retries = 3

# Address space layout randomization
kernel.randomize_va_space = 2

# Core dumps
fs.suid_dumpable = 0
kernel.core_uses_pid = 1

# Restrict dmesg
kernel.dmesg_restrict = 1

# Restrict kernel pointers
kernel.kptr_restrict = 2
SYSCTL

    log "[NETWORK] Applied comprehensive sysctl settings: $SYSCTL_FILE"
    
    # Apply settings
    if sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1; then
        success "[NETWORK] Network hardening applied"
    else
        warn "[NETWORK] Some settings may have failed (check kernel support)"
    fi
    
    # Optional: Disable IPv6
    if prompt_yes_no "Disable IPv6? (only if not needed)"; then
        log "[NETWORK] Disabling IPv6..."
        cat >> "$SYSCTL_FILE" << 'IPV6'

# IPv6 Disable
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
IPV6
        sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true
        success "[NETWORK] IPv6 disabled"
    fi
}

main "$@"
