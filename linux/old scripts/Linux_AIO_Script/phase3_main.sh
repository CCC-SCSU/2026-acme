#!/usr/bin/env bash
# phase3_main.sh - External Tools & Utilities
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
PHASE3_MARKER="$LOG_DIR/.phase3_complete"
START_TIME=$SECONDS

# Ensure log directory exists
mkdir -p "$LOG_DIR"

main() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║     AIO HARDENING - PHASE 3: TOOLS & UTILITIES            ║"
    echo "║                                                            ║"
    echo "║  External Security Tools + Helper Utilities                ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    
    # Check Phase 2 completed (only check once!)
    if [[ ! -f "$LOG_DIR/.phase2_complete" ]]; then
        warn "Phase 2 has not been run yet"
        warn "Phase 3 builds on Phase 2's configuration"
        if ! prompt_yes_no "Continue with Phase 3 anyway?"; then
            return 1
        fi
        echo ""
    fi
    
    log "PHASE 3 started at $(date)"
    echo ""
    
    # Show menu (was being called but output not shown)
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║        PHASE 3: EXTERNAL TOOLS & UTILITIES                 ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Choose installation mode:"
    echo ""
    echo "  1. Quick Install (Recommended Tools)"
    echo "     → AIDE, Fail2Ban, all utilities"
    echo ""
    echo "  2. Full Install (All Tools)"
    echo "     → Everything including Lynis, RKHunter, ClamAV"
    echo ""
    echo "  3. Custom Install (Pick and choose)"
    echo "     → Interactive menu for each tool"
    echo ""
    echo "  4. Utilities Only"
    echo "     → Skip security tools, just install utilities"
    echo ""
    echo "  5. Skip Phase 3"
    echo ""
    
    local mode
    read -r -p "Selection [1-5]: " mode
    
    case "$mode" in
        1)
            log "Quick Install Mode selected"
            quick_install
            ;;
        2)
            log "Full Install Mode selected"
            full_install
            ;;
        3)
            log "Custom Install Mode selected"
            custom_install
            ;;
        4)
            log "Utilities Only Mode selected"
            utilities_only
            ;;
        5)
            log "Phase 3 skipped by user"
            return 0
            ;;
        *)
            warn "Invalid selection. Running Quick Install."
            quick_install
            ;;
    esac
    
    # Mark Phase 3 complete
    touch "$PHASE3_MARKER"
    echo "$(date +%Y-%m-%dT%H:%M:%S%z)" > "$PHASE3_MARKER"
    
    # Calculate elapsed time
    ELAPSED=$((SECONDS - START_TIME))
    MINUTES=$((ELAPSED / 60))
    SECS=$((ELAPSED % 60))
    
    # Summary
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║            PHASE 3 COMPLETE - SUCCESS!                     ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    success "Phase 3 completed in ${MINUTES}m ${SECS}s"
    echo ""
    log "All AIO Hardening phases complete!"
    log "System is fully hardened, monitored, and equipped with tools."
}

quick_install() {
    log "Installing recommended tools..."
    
    "$SCRIPT_DIR/modules/phase3/install_aide.sh" || warn "AIDE installation had issues"
    "$SCRIPT_DIR/modules/phase3/install_fail2ban.sh" || warn "Fail2Ban installation had issues"
    "$SCRIPT_DIR/modules/phase3/install_utilities.sh" || return 1
    
    success "Quick install complete"
}

full_install() {
    log "Installing all tools..."
    
    "$SCRIPT_DIR/modules/phase3/install_aide.sh" || warn "AIDE installation had issues"
    "$SCRIPT_DIR/modules/phase3/install_fail2ban.sh" || warn "Fail2Ban installation had issues"
    "$SCRIPT_DIR/modules/phase3/install_lynis.sh" || warn "Lynis installation had issues"
    "$SCRIPT_DIR/modules/phase3/install_rkhunter.sh" || warn "RKHunter installation had issues"
    "$SCRIPT_DIR/modules/phase3/install_clamav.sh" || warn "ClamAV installation had issues"
    "$SCRIPT_DIR/modules/phase3/install_utilities.sh" || return 1
    
    success "Full install complete"
    
    echo ""
    if prompt_yes_no "Install Splunk Universal Forwarder? (requires credentials)"; then
        "$SCRIPT_DIR/modules/phase3/install_splunk.sh" || warn "Splunk installation had issues"
    fi
}

custom_install() {
    log "Custom installation mode..."
    echo ""
    
    if prompt_yes_no "Install AIDE (File Integrity Monitoring)?"; then
        "$SCRIPT_DIR/modules/phase3/install_aide.sh" || true
    fi
    
    if prompt_yes_no "Install Fail2Ban (Auto-ban malicious IPs)?"; then
        "$SCRIPT_DIR/modules/phase3/install_fail2ban.sh" || true
    fi
    
    if prompt_yes_no "Install Lynis (Security Auditing)?"; then
        "$SCRIPT_DIR/modules/phase3/install_lynis.sh" || true
    fi
    
    if prompt_yes_no "Install RKHunter (Rootkit Detection)?"; then
        "$SCRIPT_DIR/modules/phase3/install_rkhunter.sh" || true
    fi
    
    if prompt_yes_no "Install ClamAV (Antivirus)?"; then
        "$SCRIPT_DIR/modules/phase3/install_clamav.sh" || true
    fi
    
    if prompt_yes_no "Install Splunk Universal Forwarder?"; then
        "$SCRIPT_DIR/modules/phase3/install_splunk.sh" || true
    fi
    
    log "Installing utilities..."
    "$SCRIPT_DIR/modules/phase3/install_utilities.sh" || return 1
    
    success "Custom install complete"
}

utilities_only() {
    log "Installing utilities only..."
    "$SCRIPT_DIR/modules/phase3/install_utilities.sh" || return 1
    success "Utilities installed"
}

# Pre-main checks
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "ERROR: Phase 3 must be run as root"
    echo "Usage: sudo $0"
    exit 1
fi

# Run main
if ! main "$@"; then
    echo ""
    error "Phase 3 encountered errors. Check logs: $LOG_DIR/aio_master.log"
    exit 1
fi

exit 0
