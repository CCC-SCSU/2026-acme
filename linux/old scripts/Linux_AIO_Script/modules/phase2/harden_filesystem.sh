#!/usr/bin/env bash
# modules/phase2/harden_filesystem.sh - Filesystem security

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$SCRIPT_DIR/lib/logging.sh"
. "$SCRIPT_DIR/lib/prompts.sh"

LOG_DIR="/var/log/aio_hardening"

main() {
    log "[FILESYSTEM] Hardening filesystem permissions..."
    
    # Critical file permissions
    log "[FILESYSTEM] Setting critical file permissions..."
    chmod 644 /etc/passwd 2>/dev/null || true
    chmod 600 /etc/shadow 2>/dev/null || true
    chmod 644 /etc/group 2>/dev/null || true
    chmod 600 /etc/gshadow 2>/dev/null || true
    
    if [[ -f /boot/grub/grub.cfg ]]; then
        chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
    fi
    
    if [[ -f /etc/ssh/sshd_config ]]; then
        chmod 600 /etc/ssh/sshd_config 2>/dev/null || true
    fi
    
    # Find world-writable files
    log "[FILESYSTEM] Scanning for world-writable files..."
    local wwfiles="$LOG_DIR/world_writable_$(date +%Y%m%d_%H%M%S).txt"
    find /home /tmp /var/tmp -xdev -type f -perm -002 2>/dev/null > "$wwfiles" || true
    
    local count
    count=$(wc -l < "$wwfiles")
    if [[ $count -gt 0 ]]; then
        warn "[FILESYSTEM] Found $count world-writable files. List: $wwfiles"
        if prompt_yes_no "Remove world-write permission from these files?"; then
            while IFS= read -r file; do
                chmod o-w "$file" 2>/dev/null || true
            done < "$wwfiles"
            success "[FILESYSTEM] Removed world-write permissions"
        fi
    else
        log "[FILESYSTEM] No world-writable files found"
    fi
    
    # SUID/SGID scan
    log "[FILESYSTEM] Scanning for SUID/SGID binaries..."
    local suidfiles="$LOG_DIR/suid_sgid_$(date +%Y%m%d_%H%M%S).txt"
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null > "$suidfiles" || true
    
    count=$(wc -l < "$suidfiles")
    log "[FILESYSTEM] Found $count SUID/SGID files. List: $suidfiles"
    
    # Recent modifications
    log "[FILESYSTEM] Checking for recently modified files..."
    local recentfiles="$LOG_DIR/recent_modifications_$(date +%Y%m%d_%H%M%S).txt"
    find /etc /usr/bin /usr/sbin /var/www -xdev -type f -mmin -30 2>/dev/null > "$recentfiles" || true
    
    count=$(wc -l < "$recentfiles")
    if [[ $count -gt 0 ]]; then
        warn "[FILESYSTEM] Found $count files modified in last 30 minutes. List: $recentfiles"
    fi
    
    success "[FILESYSTEM] Filesystem hardening complete"
}

main "$@"
