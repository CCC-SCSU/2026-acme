#!/usr/bin/env bash
# phase2_main.sh - Comprehensive Hardening and Enumeration
# Target: 15-25 minutes for complete system hardening
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
# shellcheck source=/dev/null
. "$SCRIPT_DIR/lib/detect.sh"

# Configuration
LOG_DIR="/var/log/aio_hardening"
PHASE2_MARKER="$LOG_DIR/.phase2_complete"
REDFLAG_DIR="/var/log/redflags"
START_TIME=$SECONDS

# Ensure directories exist
mkdir -p "$LOG_DIR" "$REDFLAG_DIR"
chmod 700 "$REDFLAG_DIR"

main() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║        AIO HARDENING - PHASE 2: COMPREHENSIVE             ║"
    echo "║                                                            ║"
    echo "║  Target: Complete system hardening in 15-25 minutes        ║"
    echo "║                                                            ║"
    echo "║  Components:                                               ║"
    echo "║    • OS/Role Detection                                     ║"
    echo "║    • Service Validation                                    ║"
    echo "║    • Deep Account/Filesystem/Network Hardening             ║"
    echo "║    • Role-Specific Service Hardening                       ║"
    echo "║    • Production Firewall Configuration                     ║"
    echo "║    • Persistence Detection                                 ║"
    echo "║    • Active Monitoring Deployment                          ║"
    echo "║    • System Enumeration Tools                              ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    
    # Check Phase 1 completed
    if [[ ! -f "$LOG_DIR/.phase1_complete" ]]; then
        warn "Phase 1 marker not found"
        warn "It's recommended to run Phase 1 first for emergency lockdown"
        if ! prompt_yes_no "Continue with Phase 2 anyway?"; then
            die "Aborted. Run Phase 1 first: sudo ./phase1_main.sh"
        fi
    fi
    
    log "PHASE 2 started at $(date)"
    log "Logs: $LOG_DIR/"
    log "Red flags: $REDFLAG_DIR/"
    echo ""
    
    # 2.1 OS and Role Detection
    log "→ Step 1/11: System and Role Detection"
    if ! "$SCRIPT_DIR/modules/phase2/detect_system.sh"; then
        error "System detection failed"
        return 1
    fi
    echo ""
    
    # Load detected role
    if [[ -f "$LOG_DIR/detected_role.conf" ]]; then
        # shellcheck source=/dev/null
        . "$LOG_DIR/detected_role.conf"
        log "Loaded role: ${ROLE:-unknown}"
    fi
    
    # 2.2 Service Validation
    log "→ Step 2/11: Service Validation"
    if ! "$SCRIPT_DIR/modules/phase2/validate_services.sh"; then
        error "Service validation failed"
        return 1
    fi
    echo ""
    
    # 2.3 Account Hardening
    log "→ Step 3/11: Deep Account Hardening"
    if ! "$SCRIPT_DIR/modules/phase2/harden_accounts.sh"; then
        error "Account hardening failed"
        return 1
    fi
    echo ""
    
    # 2.4 Filesystem Hardening
    log "→ Step 4/11: Filesystem Hardening"
    if ! "$SCRIPT_DIR/modules/phase2/harden_filesystem.sh"; then
        error "Filesystem hardening failed"
        return 1
    fi
    echo ""
    
    # 2.5 Network Hardening
    log "→ Step 5/11: Network Hardening"
    if ! "$SCRIPT_DIR/modules/phase2/harden_network.sh"; then
        error "Network hardening failed"
        return 1
    fi
    echo ""
    
    # 2.6 Service-Specific Hardening
    log "→ Step 6/11: Service-Specific Hardening"
    if ! "$SCRIPT_DIR/modules/phase2/harden_services.sh"; then
        error "Service hardening failed"
        return 1
    fi
    echo ""
    
    # 2.7 Production Firewall
    log "→ Step 7/11: Production Firewall Configuration"
    if ! "$SCRIPT_DIR/modules/phase2/configure_firewall.sh"; then
        error "Firewall configuration failed"
        return 1
    fi
    echo ""
    
    # 2.8 Persistence Detection
    log "→ Step 8/11: Persistence Detection"
    if ! "$SCRIPT_DIR/modules/phase2/detect_persistence.sh"; then
        error "Persistence detection failed"
        return 1
    fi
    echo ""
    
    # 2.9 Monitoring Setup
    log "→ Step 9/11: Active Monitoring Deployment"
    if ! "$SCRIPT_DIR/modules/phase2/setup_monitoring.sh"; then
        error "Monitoring setup failed"
        return 1
    fi
    echo ""
    
    # 2.10 Logging Configuration
    log "→ Step 10/11: Logging Configuration"
    if ! "$SCRIPT_DIR/modules/phase2/configure_logging.sh"; then
        error "Logging configuration failed"
        return 1
    fi
    echo ""
    
    # 2.11 Enumeration Tools
    log "→ Step 11/11: Installing Enumeration Tools"
    if ! "$SCRIPT_DIR/modules/phase2/install_enum_tools.sh"; then
        error "Enumeration tools installation failed"
        return 1
    fi
    echo ""
    
    # Mark Phase 2 complete
    touch "$PHASE2_MARKER"
    echo "$(date +%Y-%m-%dT%H:%M:%S%z)" > "$PHASE2_MARKER"
    
    # Calculate elapsed time
    ELAPSED=$((SECONDS - START_TIME))
    MINUTES=$((ELAPSED / 60))
    SECS=$((ELAPSED % 60))
    
    # Summary
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║            PHASE 2 COMPLETE - SUCCESS!                     ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    success "Phase 2 completed in ${MINUTES}m ${SECS}s"
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo " ✅ WHAT WAS ACCOMPLISHED"
    echo "════════════════════════════════════════════════════════════"
    echo ""
    echo " System Hardening:"
    echo "   ✓ Accounts hardened (locked, password policies, SSH keys checked)"
    echo "   ✓ Filesystem secured (permissions, SUID scan, world-writable removed)"
    echo "   ✓ Network hardened (comprehensive sysctl settings)"
    echo "   ✓ Services hardened (role-specific configurations)"
    echo "   ✓ Production firewall active (role-based rules)"
    echo ""
    echo " Security Monitoring:"
    echo "   ✓ 5 active monitors deployed to $REDFLAG_DIR/"
    echo "   ✓ Process monitor (watching for new processes)"
    echo "   ✓ Network monitor (watching for new connections)"
    echo "   ✓ File monitor (watching critical directories)"
    echo "   ✓ User monitor (watching for account changes)"
    echo "   ✓ Cron monitor (watching for new cron jobs)"
    echo ""
    echo " Enumeration Tools:"
    echo "   ✓ Port scanner (aio-enum-ports)"
    echo "   ✓ Service enumerator (aio-enum-services)"
    echo "   ✓ User enumerator (aio-enum-users)"
    echo "   ✓ Network enumerator (aio-enum-network)"
    echo "   ✓ Package enumerator (aio-enum-packages)"
    echo "   ✓ Persistence finder (aio-enum-persistence)"
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo " 🔍 CHECK RED FLAGS"
    echo "════════════════════════════════════════════════════════════"
    echo ""
    echo " Monitor logs for suspicious activity:"
    echo "   tail -f $REDFLAG_DIR/new_processes.log"
    echo "   tail -f $REDFLAG_DIR/new_connections.log"
    echo "   tail -f $REDFLAG_DIR/file_changes.log"
    echo ""
    echo " Or use the red flag summary tool:"
    echo "   sudo aio-redflags --last-hour"
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo " 📋 NEXT STEPS"
    echo "════════════════════════════════════════════════════════════"
    echo ""
    echo " → Phase 3: External tools and utilities"
    echo "   - Install security tools (AIDE, Fail2Ban, etc.)"
    echo "   - Deploy utility scripts (backups, log checking, etc.)"
    echo "   - Run: sudo ./phase3_main.sh"
    echo ""
    echo " → Run enumeration to check current state:"
    echo "   sudo aio-enum-ports"
    echo "   sudo aio-enum-services"
    echo "   sudo aio-enum-users"
    echo ""
    echo " → Monitor for red team activity:"
    echo "   watch -n 10 'sudo aio-redflags --last-hour'"
    echo ""
    
    log "Phase 2 complete. System is hardened and monitored."
}

# Pre-main checks
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "ERROR: Phase 2 must be run as root"
    echo "Usage: sudo $0"
    exit 1
fi

# Run main
if ! main "$@"; then
    echo ""
    error "Phase 2 encountered errors. Check logs: $LOG_DIR/aio_master.log"
    exit 1
fi

exit 0
