#!/usr/bin/env bash
# modules/phase2/harden_accounts.sh - Deep account hardening

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$SCRIPT_DIR/lib/logging.sh"
. "$SCRIPT_DIR/lib/prompts.sh"

LOG_DIR="/var/log/aio_hardening"

main() {
    log "[ACCOUNTS] Deep account hardening..."
    
    local report="$LOG_DIR/account_audit_$(date +%Y%m%d_%H%M%S).txt"
    
    # Lock system accounts
    log "[ACCOUNTS] Locking system service accounts..."
    for user in daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc gnats nobody systemd-network systemd-resolve; do
        if id "$user" >/dev/null 2>&1; then
            usermod -L "$user" 2>/dev/null || true
            usermod -s /usr/sbin/nologin "$user" 2>/dev/null || usermod -s /sbin/nologin "$user" 2>/dev/null || true
        fi
    done
    
    # Check for UID 0 accounts
    log "[ACCOUNTS] Checking for unauthorized UID 0 accounts..."
    awk -F: '$3 == 0 && $1 != "root" {print "CRITICAL: UID 0 account found: " $1}' /etc/passwd | tee -a "$report"
    
    # Check for empty passwords
    log "[ACCOUNTS] Checking for empty passwords..."
    awk -F: '$2 == "" {print "CRITICAL: Empty password for: " $1}' /etc/shadow 2>/dev/null | tee -a "$report" || true
    
    # Remove dangerous files from home directories
    log "[ACCOUNTS] Removing .rhosts and .netrc files..."
    find /home -name ".rhosts" -delete 2>/dev/null || true
    find /home -name ".netrc" -delete 2>/dev/null || true
    
    # Check SSH keys
    log "[ACCOUNTS] Auditing SSH authorized_keys..."
    find /home -name "authorized_keys" -type f 2>/dev/null | while read -r keyfile; do
        if [[ -s "$keyfile" ]]; then
            echo "SSH keys found: $keyfile" >> "$report"
            wc -l < "$keyfile" | xargs echo "  Number of keys:" >> "$report"
        fi
    done
    
    # Check /root/.ssh too
    if [[ -f /root/.ssh/authorized_keys ]]; then
        echo "Root SSH keys: /root/.ssh/authorized_keys" >> "$report"
        wc -l < /root/.ssh/authorized_keys | xargs echo "  Number of keys:" >> "$report"
    fi
    
    success "[ACCOUNTS] Account hardening complete. Report: $report"
}

main "$@"
