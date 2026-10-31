#!/usr/bin/env bash
# Install and configure Fail2Ban
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$SCRIPT_DIR/lib/logging.sh"
. "$SCRIPT_DIR/lib/detect.sh"

main() {
    log "[FAIL2BAN] Installing Fail2Ban..."
    
    local pkg_mgr
    pkg_mgr=$(detect_package_manager)
    
    case "$pkg_mgr" in
        apt)
            apt-get update -qq
            apt-get install -y fail2ban
            ;;
        yum|dnf)
            $pkg_mgr install -y fail2ban fail2ban-systemd
            ;;
        *)
            error "[FAIL2BAN] Unsupported package manager"
            return 1
            ;;
    esac
    
    log "[FAIL2BAN] Configuring jails..."
    
    # Check if config already exists (don't overwrite competition config!)
    if [[ -f /etc/fail2ban/jail.local ]]; then
        warn "[FAIL2BAN] /etc/fail2ban/jail.local already exists!"
        if ! prompt_yes_no "Overwrite existing Fail2Ban configuration?"; then
            log "[FAIL2BAN] Keeping existing configuration"
            systemctl enable fail2ban 2>/dev/null || true
            systemctl restart fail2ban 2>/dev/null || true
            success "[FAIL2BAN] Installed (kept existing config)"
            return 0
        fi
    fi
    
    cat > /etc/fail2ban/jail.local << 'F2BCONF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
destemail = root@localhost
action = %(action_mwl)s

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
backend = systemd

[apache-auth]
enabled = true
port = http,https
logpath = /var/log/apache*/*error.log

[postfix]
enabled = true
port = smtp,ssmtp,submission
logpath = /var/log/mail.log
F2BCONF

    systemctl enable fail2ban
    systemctl restart fail2ban
    
    if systemctl is-active --quiet fail2ban; then
        success "[FAIL2BAN] Installed, configured, and active"
    else
        error "[FAIL2BAN] Installation succeeded but service not active"
        return 1
    fi
    
    log "[FAIL2BAN] Check status: fail2ban-client status"
}

main "$@"
