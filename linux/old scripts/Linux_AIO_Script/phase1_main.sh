#!/usr/bin/env bash
# phase1_main.sh - Emergency "First Five" Lockdown
# Target: 2-5 minutes to stop active exploitation
# Part of AIO Hardening Script for CCDC competitions

set -euo pipefail
IFS=$'\n\t'

# Determine script root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source libraries
# shellcheck source=/dev/null
. "$SCRIPT_DIR/lib/logging.sh"
# shellcheck source=/dev/null
. "$SCRIPT_DIR/lib/prompts.sh"

# Configuration
LOG_DIR="/var/log/aio_hardening"
PHASE1_MARKER="$LOG_DIR/.phase1_complete"
START_TIME=$SECONDS

# Ensure log directory exists
mkdir -p "$LOG_DIR"

main() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║          AIO HARDENING - PHASE 1: EMERGENCY LOCKDOWN       ║"
    echo "║                                                            ║"
    echo "║  Target: Stop active red team exploitation in 2-5 minutes  ║"
    echo "║                                                            ║"
    echo "║  Components:                                               ║"
    echo "║    1. Pre-flight checks                                    ║"
    echo "║    2. Emergency firewall lockdown                          ║"
    echo "║    3. SSH termination                                      ║"
    echo "║    4. New admin user creation                              ║"
    echo "║    5. Kernel hardening                                     ║"
    echo "║    6. Process baseline & cleanup                           ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    
    log "PHASE 1 started at $(date)"
    log "Logs: $LOG_DIR/"
    echo ""
    
    # 1.1 Pre-flight checks
    log "→ Step 1/6: Pre-flight checks"
    if ! "$SCRIPT_DIR/modules/phase1/preflight.sh"; then
        error "Pre-flight checks failed"
        return 1
    fi
    echo ""
    
    # 1.2 Emergency firewall
    log "→ Step 2/6: Emergency firewall lockdown"
    if ! "$SCRIPT_DIR/modules/phase1/firewall_emergency.sh"; then
        error "Firewall configuration failed"
        return 1
    fi
    echo ""
    
    # 1.3 SSH termination
    log "→ Step 3/6: SSH termination"
    if ! "$SCRIPT_DIR/modules/phase1/ssh_terminate.sh"; then
        error "SSH termination failed"
        return 1
    fi
    echo ""
    
    # 1.4 User creation
    log "→ Step 4/6: New administrative user"
    if ! "$SCRIPT_DIR/modules/phase1/user_create.sh"; then
        error "User creation failed"
        return 1
    fi
    echo ""
    
    # 1.5 Quick kernel hardening
    log "→ Step 5/6: Kernel hardening"
    if ! "$SCRIPT_DIR/modules/phase1/kernel_harden.sh"; then
        error "Kernel hardening failed"
        return 1
    fi
    echo ""
    
    # 1.6 Process baseline & cleanup
    log "→ Step 6/6: Process baseline & cleanup"
    if ! "$SCRIPT_DIR/modules/phase1/process_baseline.sh"; then
        error "Process baseline failed"
        return 1
    fi
    echo ""
    
    # Mark Phase 1 complete
    touch "$PHASE1_MARKER"
    echo "$(date +%Y-%m-%dT%H:%M:%S%z)" > "$PHASE1_MARKER"
    
    # Calculate elapsed time
    ELAPSED=$((SECONDS - START_TIME))
    MINUTES=$((ELAPSED / 60))
    SECS=$((ELAPSED % 60))
    
    # Summary
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║              PHASE 1 COMPLETE - SUCCESS!                   ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    success "Phase 1 completed in ${MINUTES}m ${SECS}s"
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo " ⚠  CRITICAL REMINDERS"
    echo "════════════════════════════════════════════════════════════"
    echo ""
    echo " 1. TEST CONSOLE ACCESS NOW before logging out!"
    echo "    - Open new terminal/console"
    echo "    - Login with new user"
    echo "    - Test: sudo -v"
    echo ""
    echo " 2. Verify security:"
    echo "    - SSH is disabled: systemctl status sshd"
    echo "    - Firewall is active: iptables -L -n"
    echo "    - New user has sudo: groups <username>"
    echo ""
    echo " 3. Check logs for any errors:"
    echo "    - tail -f $LOG_DIR/aio_master.log"
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo " 📋 NEXT STEPS"
    echo "════════════════════════════════════════════════════════════"
    echo ""
    echo " → Phase 2: Comprehensive hardening (coming soon)"
    echo "   - OS/role detection"
    echo "   - Service validation"  
    echo "   - Deep hardening"
    echo "   - Monitoring setup"
    echo ""
    echo " → Check service status manually:"
    echo "   - Verify scoring services are configured"
    echo "   - Apply Phase 2 when ready"
    echo ""
    log "Phase 1 complete. Exiting."
}

# Pre-main checks
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "ERROR: Phase 1 must be run as root"
    echo "Usage: sudo $0"
    exit 1
fi

# Run main
if ! main "$@"; then
    echo ""
    error "Phase 1 encountered errors. Check logs: $LOG_DIR/aio_master.log"
    exit 1
fi

exit 0
