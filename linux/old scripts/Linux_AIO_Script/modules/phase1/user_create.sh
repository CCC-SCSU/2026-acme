#!/usr/bin/env bash
# modules/phase1/user_create.sh - Create new administrative user

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=/dev/null
. "$SCRIPT_DIR/lib/logging.sh"
# shellcheck source=/dev/null
. "$SCRIPT_DIR/lib/prompts.sh"

# Common weak usernames to reject
WEAK_USERNAMES=(
    "admin" "administrator" "root" "user" "test" "guest" 
    "oracle" "postgres" "mysql" "apache" "nginx" "www"
    "ubuntu" "centos" "redhat" "debian" "fedora"
)

main() {
    log "[USER] Creating new administrative user..."
    
    # Lock unnecessary system accounts first
    log "[USER] Locking unnecessary system accounts..."
    for user in games sync shutdown halt operator lp mail news uucp proxy www-data backup list irc gnats nobody; do
        if id "$user" >/dev/null 2>&1; then
            usermod -L "$user" 2>/dev/null || true
            usermod -s /usr/sbin/nologin "$user" 2>/dev/null || true
        fi
    done
    
    # Prompt for username
    local new_username
    while true; do
        echo ""
        read -r -p "Enter new administrative username: " new_username
        
        # Validate username
        if [[ -z "$new_username" ]]; then
            warn "Username cannot be empty"
            continue
        fi
        
        if [[ ! "$new_username" =~ ^[a-z][a-z0-9_-]{2,15}$ ]]; then
            warn "Invalid username format"
            warn "Requirements: 3-16 chars, start with lowercase letter, only lowercase letters, numbers, - and _"
            continue
        fi
        
        # Check against weak usernames
        local is_weak=0
        for weak in "${WEAK_USERNAMES[@]}"; do
            if [[ "$new_username" == "$weak" ]]; then
                warn "Username '$new_username' is too common/weak"
                is_weak=1
                break
            fi
        done
        if [[ $is_weak -eq 1 ]]; then
            continue
        fi
        
        # Check if already exists
        if id "$new_username" >/dev/null 2>&1; then
            warn "User '$new_username' already exists"
            continue
        fi
        
        # Confirm
        if prompt_yes_no "Create user '$new_username'?"; then
            break
        fi
    done
    
    # Create user
    log "[USER] Creating user: $new_username"
    if ! useradd -m -s /bin/bash "$new_username"; then
        die "[USER] Failed to create user"
    fi
    
    # Set password interactively
    log "[USER] Set password for $new_username (interactive)..."
    echo ""
    echo "=== SET PASSWORD FOR $new_username ==="
    if ! passwd "$new_username"; then
        error "[USER] Password set failed!"
        warn "[USER] Removing incomplete user..."
        userdel -r "$new_username" 2>/dev/null || true
        die "[USER] User creation failed - password not set"
    fi
    
    # Add to sudo/wheel group
    log "[USER] Adding $new_username to sudo/wheel group..."
    local sudo_group=""
    if getent group sudo >/dev/null 2>&1; then
        sudo_group="sudo"
    elif getent group wheel >/dev/null 2>&1; then
        sudo_group="wheel"
    else
        warn "[USER] Neither 'sudo' nor 'wheel' group exists!"
        warn "[USER] Creating 'sudo' group..."
        groupadd sudo || die "[USER] Failed to create sudo group"
        sudo_group="sudo"
        
        # Add sudo group to sudoers if needed
        if ! grep -q "^%sudo" /etc/sudoers 2>/dev/null; then
            echo "%sudo   ALL=(ALL:ALL) ALL" >> /etc/sudoers
        fi
    fi
    
    usermod -aG "$sudo_group" "$new_username" || die "[USER] Failed to add user to $sudo_group group"
    
    # Verify group membership
    if groups "$new_username" | grep -q "$sudo_group"; then
        success "[USER] User $new_username added to $sudo_group group"
    else
        die "[USER] Group membership verification failed"
    fi
    
    # Optional: Test sudo access
    echo ""
    if prompt_yes_no "Test sudo access for $new_username? (recommended)"; then
        log "[USER] Testing sudo access..."
        if su - "$new_username" -c "sudo -v" 2>/dev/null; then
            success "[USER] Sudo access verified!"
        else
            warn "[USER] Sudo test failed - may need manual verification"
        fi
    fi
    
    success "[USER] User $new_username created successfully"
    echo ""
    warn "IMPORTANT: Test console login with $new_username BEFORE logging out!"
}

main "$@"
