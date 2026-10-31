#!/usr/bin/env bash
# modules/phase2/configure_firewall.sh - Production firewall rules

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$SCRIPT_DIR/lib/logging.sh"
. "$SCRIPT_DIR/lib/prompts.sh"

LOG_DIR="/var/log/aio_hardening"
ROLE_FILE="$LOG_DIR/detected_role.conf"

detect_firewall() {
    # Detect which firewall to use
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

configure_ufw() {
    local ports="$1"
    local allow_icmp="$2"
    
    log "[FIREWALL] Configuring UFW..."
    
    # Disable first to start fresh
    ufw --force disable 2>/dev/null || true
    
    # Reset to defaults
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow loopback
    ufw allow in on lo
    ufw allow out on lo
    
    # Allow role-specific ports
    if [[ -n "$ports" ]]; then
        IFS=',' read -ra PORTS <<< "$ports"
        for port in "${PORTS[@]}"; do
            ufw allow "$port/tcp"
            log "[FIREWALL] UFW: Allowed TCP port $port"
        done
    fi
    
    # ICMP
    if [[ "$allow_icmp" == "yes" ]]; then
        ufw allow proto icmp
        log "[FIREWALL] UFW: ICMP allowed"
    fi
    
    # Deny outbound SSH (defense in depth)
    ufw deny out 22/tcp
    ufw deny out 4444/tcp
    ufw deny out 1337/tcp
    ufw deny out 31337/tcp
    
    # Enable UFW
    log "[FIREWALL] Enabling UFW..."
    ufw --force enable
    
    # Verify it's active
    if ufw status | grep -q "Status: active"; then
        success "[FIREWALL] UFW is active and enabled"
    else
        error "[FIREWALL] UFW failed to activate!"
        return 1
    fi
    
    # Show status
    echo ""
    log "[FIREWALL] UFW Status:"
    ufw status verbose
}

configure_firewalld() {
    local ports="$1"
    local allow_icmp="$2"
    
    log "[FIREWALL] Configuring firewalld..."
    
    # Start firewalld if not running
    if ! systemctl is-active --quiet firewalld; then
        log "[FIREWALL] Starting firewalld..."
        systemctl start firewalld
    fi
    
    # Set default zone to drop
    firewall-cmd --set-default-zone=drop
    
    # Create a custom zone for our rules
    firewall-cmd --permanent --new-zone=ccdc 2>/dev/null || true
    firewall-cmd --reload
    
    # Set ccdc as default
    firewall-cmd --set-default-zone=ccdc
    
    # Allow loopback
    firewall-cmd --permanent --zone=ccdc --add-interface=lo
    
    # Allow role-specific ports
    if [[ -n "$ports" ]]; then
        IFS=',' read -ra PORTS <<< "$ports"
        for port in "${PORTS[@]}"; do
            firewall-cmd --permanent --zone=ccdc --add-port="${port}/tcp"
            log "[FIREWALL] firewalld: Allowed TCP port $port"
        done
    fi
    
    # ICMP
    if [[ "$allow_icmp" == "yes" ]]; then
        firewall-cmd --permanent --zone=ccdc --add-icmp-block-inversion
        log "[FIREWALL] firewalld: ICMP allowed"
    fi
    
    # Deny outbound on specific ports (rich rules)
    firewall-cmd --permanent --zone=ccdc --add-rich-rule='rule family="ipv4" port port="22" protocol="tcp" drop'
    firewall-cmd --permanent --zone=ccdc --add-rich-rule='rule family="ipv4" port port="4444" protocol="tcp" drop'
    
    # Reload to apply
    firewall-cmd --reload
    
    # Enable firewalld
    log "[FIREWALL] Enabling firewalld..."
    systemctl enable firewalld
    
    # Verify it's active
    if systemctl is-active --quiet firewalld; then
        success "[FIREWALL] firewalld is active and enabled"
    else
        error "[FIREWALL] firewalld failed to activate!"
        return 1
    fi
    
    # Show status
    echo ""
    log "[FIREWALL] firewalld Status:"
    firewall-cmd --list-all
}

configure_iptables() {
    local ports="$1"
    local allow_icmp="$2"
    
    log "[FIREWALL] Configuring iptables..."
    
    # Backup current rules
    local backup="$LOG_DIR/firewall_phase2_backup_$(date +%Y%m%d_%H%M%S).rules"
    iptables-save > "$backup" 2>/dev/null || true
    log "[FIREWALL] Backed up current rules to: $backup"
    
    # Flush and set defaults
    iptables -F
    iptables -X
    iptables -Z
    
    # Default policies
    iptables -P INPUT DROP
    iptables -P OUTPUT ACCEPT
    iptables -P FORWARD DROP
    
    # Loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Established/related
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow role-specific ports
    if [[ -n "$ports" ]]; then
        IFS=',' read -ra PORTS <<< "$ports"
        for port in "${PORTS[@]}"; do
            iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
            log "[FIREWALL] iptables: Allowed TCP port $port"
        done
    fi
    
    # ICMP
    if [[ "$allow_icmp" == "yes" ]]; then
        iptables -A INPUT -p icmp -j ACCEPT
        log "[FIREWALL] iptables: ICMP allowed"
    fi
    
    # Outbound restrictions (defense in depth)
    iptables -A OUTPUT -p tcp --dport 22 -j DROP
    iptables -A OUTPUT -p tcp --dport 4444 -j DROP
    iptables -A OUTPUT -p tcp --dport 1337 -j DROP
    iptables -A OUTPUT -p tcp --dport 31337 -j DROP
    
    # Make persistent
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    
    # Create systemd service for persistence (if systemd)
    if command -v systemctl >/dev/null 2>&1; then
        cat > /etc/systemd/system/iptables-restore.service << 'SERVICE'
[Unit]
Description=Restore iptables rules
Before=network-pre.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables/rules.v4
ExecStop=/sbin/iptables-save -f /etc/iptables/rules.v4
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICE
        systemctl daemon-reload
        systemctl enable iptables-restore.service 2>/dev/null || true
    fi
    
    success "[FIREWALL] iptables configured and rules saved"
    
    # Display final rules
    echo ""
    log "[FIREWALL] Active iptables rules:"
    iptables -L -n -v | head -30
}

main() {
    log "[FIREWALL] Configuring production firewall rules..."
    
    # Load role
    local ports=""
    local role="unknown"
    
    if [[ -f "$ROLE_FILE" ]]; then
        . "$ROLE_FILE"
        ports="$PORTS_TCP"
        role="$ROLE"
        log "[FIREWALL] Configuring for role: $role"
        log "[FIREWALL] Allowed TCP ports: $ports"
    else
        warn "[FIREWALL] No role detected. Will configure minimal firewall."
    fi
    
    # Detect firewall
    local fw_type
    fw_type=$(detect_firewall)
    log "[FIREWALL] Detected firewall type: $fw_type"
    
    # Ask about ICMP
    local allow_icmp="no"
    if prompt_yes_no "Allow ICMP (ping)?"; then
        allow_icmp="yes"
    fi
    
    # Configure based on detected firewall
    case "$fw_type" in
        ufw)
            configure_ufw "$ports" "$allow_icmp"
            ;;
        firewalld)
            configure_firewalld "$ports" "$allow_icmp"
            ;;
        iptables)
            configure_iptables "$ports" "$allow_icmp"
            ;;
        none)
            error "[FIREWALL] No firewall found! Install ufw, firewalld, or iptables."
            return 1
            ;;
    esac
    
    success "[FIREWALL] Production firewall active and configured"
    
    # Final verification
    echo ""
    log "[FIREWALL] Verification:"
    case "$fw_type" in
        ufw)
            ufw status | grep "Status:" || true
            ;;
        firewalld)
            systemctl is-active firewalld && log "✓ firewalld is running" || error "✗ firewalld is NOT running"
            ;;
        iptables)
            iptables -L -n | grep -q "Chain INPUT" && log "✓ iptables rules are active" || error "✗ iptables rules NOT active"
            ;;
    esac
}

main "$@"
