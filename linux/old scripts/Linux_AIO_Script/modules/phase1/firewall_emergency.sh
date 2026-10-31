#!/usr/bin/env bash
# modules/phase1/firewall_emergency.sh - Emergency firewall lockdown

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=/dev/null
. "$SCRIPT_DIR/lib/logging.sh"
# shellcheck source=/dev/null
. "$SCRIPT_DIR/lib/prompts.sh"

LOG_DIR="/var/log/aio_hardening"

detect_firewall() {
    if command -v ufw >/dev/null 2>&1; then
        echo "ufw"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        echo "firewalld"
    elif command -v iptables >/dev/null 2>&1; then
        echo "iptables"
    else
        echo "none"
    fi
}

main() {
    log "[FIREWALL] Emergency firewall lockdown starting..."
    
    # Detect firewall
    local fw_type
    fw_type=$(detect_firewall)
    log "[FIREWALL] Detected firewall type: $fw_type"
    
    # Backup if using iptables
    if [[ "$fw_type" == "iptables" ]] || [[ "$fw_type" == "ufw" ]]; then
        local backup="$LOG_DIR/firewall_backup_$(date +%Y%m%d_%H%M%S).rules"
        iptables-save > "$backup" 2>/dev/null || warn "Could not backup iptables"
        log "[FIREWALL] Backup saved to: $backup"
    fi
    
    # Prompt for firewall mode
    echo ""
    echo "=== FIREWALL MODE SELECTION ==="
    echo ""
    echo "1. FULL BLACKOUT (deny inbound AND outbound)"
    echo "   - Maximum security"
    echo "   - Cannot download additional scripts"
    echo "   - Use for 'nuclear option' strategy"
    echo ""
    echo "2. DENY INBOUND ONLY (allow outbound)"
    echo "   - Good security"
    echo "   - Can still download scripts/updates"
    echo "   - Recommended for most cases"
    echo ""
    echo "3. SKIP FIREWALL"
    echo "   - Manual firewall management"
    echo "   - Not recommended"
    echo ""
    
    local choice
    read -r -p "Select firewall mode [1-3]: " choice
    
    case "$choice" in
        1)
            apply_full_blackout "$fw_type"
            ;;
        2)
            apply_inbound_only "$fw_type"
            ;;
        3)
            warn "[FIREWALL] Skipping firewall configuration"
            return 0
            ;;
        *)
            warn "[FIREWALL] Invalid choice. Applying inbound-only (safe default)"
            apply_inbound_only "$fw_type"
            ;;
    esac
    
    success "[FIREWALL] Emergency firewall applied and active"
}

apply_full_blackout() {
    local fw_type="$1"
    log "[FIREWALL] Applying FULL BLACKOUT mode..."
    
    case "$fw_type" in
        ufw)
            ufw --force disable 2>/dev/null || true
            ufw --force reset
            ufw default deny incoming
            ufw default deny outgoing
            ufw allow in on lo
            ufw allow out on lo
            ufw --force enable
            log "[FIREWALL] UFW: Full blackout applied and enabled"
            ;;
        firewalld)
            systemctl start firewalld 2>/dev/null || true
            firewall-cmd --set-default-zone=drop
            firewall-cmd --permanent --zone=drop --add-interface=lo
            firewall-cmd --reload
            systemctl enable firewalld
            log "[FIREWALL] firewalld: Full blackout applied and enabled"
            ;;
        iptables)
            iptables -F
            iptables -X
            iptables -Z
            iptables -P INPUT DROP
            iptables -P OUTPUT DROP
            iptables -P FORWARD DROP
            iptables -A INPUT -i lo -j ACCEPT
            iptables -A OUTPUT -o lo -j ACCEPT
            log "[FIREWALL] iptables: Full blackout applied"
            ;;
    esac
}

apply_inbound_only() {
    local fw_type="$1"
    log "[FIREWALL] Applying INBOUND-ONLY deny mode..."
    
    case "$fw_type" in
        ufw)
            ufw --force disable 2>/dev/null || true
            ufw --force reset
            ufw default deny incoming
            ufw default allow outgoing
            ufw allow in on lo
            ufw --force enable
            log "[FIREWALL] UFW: Inbound deny applied and enabled"
            ufw status verbose
            ;;
        firewalld)
            systemctl start firewalld 2>/dev/null || true
            firewall-cmd --permanent --new-zone=phase1 2>/dev/null || true
            firewall-cmd --reload
            firewall-cmd --set-default-zone=phase1
            firewall-cmd --permanent --zone=phase1 --add-interface=lo
            firewall-cmd --reload
            systemctl enable firewalld
            log "[FIREWALL] firewalld: Inbound deny applied and enabled"
            firewall-cmd --list-all
            ;;
        iptables)
            iptables -F
            iptables -X
            iptables -Z
            iptables -P INPUT DROP
            iptables -P OUTPUT ACCEPT
            iptables -P FORWARD DROP
            iptables -A INPUT -i lo -j ACCEPT
            iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
            log "[FIREWALL] iptables: Inbound deny applied"
            ;;
    esac
}

main "$@"
