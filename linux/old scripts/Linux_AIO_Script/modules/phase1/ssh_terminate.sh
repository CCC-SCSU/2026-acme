#!/usr/bin/env bash
# modules/phase1/ssh_terminate.sh - SSH termination

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=/dev/null
. "$SCRIPT_DIR/lib/logging.sh"
# shellcheck source=/dev/null
. "$SCRIPT_DIR/lib/prompts.sh"
# shellcheck source=/dev/null
. "$SCRIPT_DIR/lib/detect.sh"

main() {
    log "[SSH] Terminating SSH access..."
    
    # Kill all SSH processes
    log "[SSH] Killing all sshd processes..."
    pkill -9 sshd 2>/dev/null || log "[SSH] No sshd processes found"
    
    # Stop SSH service
    local init_system
    init_system=$(detect_init)
    
    if [[ "$init_system" == "systemd" ]]; then
        log "[SSH] Stopping SSH service (systemd)..."
        systemctl stop sshd 2>/dev/null || systemctl stop ssh 2>/dev/null || log "[SSH] SSH service not found"
        
        log "[SSH] Masking SSH service..."
        systemctl mask sshd 2>/dev/null || systemctl mask ssh 2>/dev/null || log "[SSH] Could not mask SSH"
    else
        log "[SSH] Stopping SSH service (sysvinit)..."
        service sshd stop 2>/dev/null || service ssh stop 2>/dev/null || log "[SSH] SSH service not found"
        
        # Disable in init.d
        if [ -f /etc/init.d/sshd ]; then
            chmod -x /etc/init.d/sshd 2>/dev/null || true
        fi
        if [ -f /etc/init.d/ssh ]; then
            chmod -x /etc/init.d/ssh 2>/dev/null || true
        fi
    fi
    
    # Ask about package removal
    echo ""
    if prompt_yes_no "Remove SSH package completely? (aggressive)"; then
        log "[SSH] Removing SSH package..."
        local pkg_mgr
        pkg_mgr=$(detect_package_manager)
        
        case "$pkg_mgr" in
            apt)
                apt-get remove -y openssh-server 2>/dev/null || warn "[SSH] Could not remove package"
                ;;
            yum|dnf)
                $pkg_mgr remove -y openssh-server 2>/dev/null || warn "[SSH] Could not remove package"
                ;;
            *)
                warn "[SSH] Unknown package manager, skipping package removal"
                ;;
        esac
    else
        log "[SSH] Keeping SSH package (service disabled)"
    fi
    
    success "[SSH] SSH access terminated"
}

main "$@"
