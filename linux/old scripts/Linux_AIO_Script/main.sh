#!/usr/bin/env bash
# main.sh - AIO Hardening Script Master Controller
# Single entry point for all phases
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
START_TIME=$SECONDS

# Ensure log directory exists
mkdir -p "$LOG_DIR"

show_banner() {
    cat << 'BANNER'
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║              AIO HARDENING SCRIPT - MAIN MENU                 ║
║                                                               ║
║        Comprehensive Hardening for CCDC Competitions          ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
BANNER
}

show_menu() {
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo " AVAILABLE PHASES"
    echo "════════════════════════════════════════════════════════════"
    echo ""
    
    # Check what's completed
    local phase1_status="[ ]"
    local phase2_status="[ ]"
    local phase3_status="[ ]"
    
    if [[ -f "$LOG_DIR/.phase1_complete" ]]; then
        phase1_status="[✓]"
    fi
    if [[ -f "$LOG_DIR/.phase2_complete" ]]; then
        phase2_status="[✓]"
    fi
    if [[ -f "$LOG_DIR/.phase3_complete" ]]; then
        phase3_status="[✓]"
    fi
    
    echo "  1. ${phase1_status} Phase 1: Emergency Lockdown (2-5 min)"
    echo "      - Emergency firewall, SSH termination, user creation"
    echo "      - Kernel hardening, process cleanup"
    echo ""
    echo "  2. ${phase2_status} Phase 2: Comprehensive Hardening (15-25 min)"
    echo "      - Deep system hardening, service configuration"
    echo "      - Active monitoring, enumeration tools"
    echo ""
    echo "  3. ${phase3_status} Phase 3: External Tools & Utilities (variable)"
    echo "      - Security tools (AIDE, Fail2Ban, etc.)"
    echo "      - Utility scripts (backups, log checking, etc.)"
    echo ""
    echo "  4. Run All Phases (Phase 1 → 2 → 3)"
    echo ""
    echo "  5. Quick Actions Menu"
    echo "      - Verify hardening, check services, view logs"
    echo ""
    echo "  6. Exit"
    echo ""
    echo "════════════════════════════════════════════════════════════"
}

run_phase1() {
    log "Starting Phase 1: Emergency Lockdown"
    
    if [[ ! -f "$SCRIPT_DIR/phase1_main.sh" ]]; then
        error "Phase 1 script not found: $SCRIPT_DIR/phase1_main.sh"
        return 1
    fi
    
    # Temporarily disable exit on error for this call
    set +e
    "$SCRIPT_DIR/phase1_main.sh"
    local exit_code=$?
    set -e
    
    if [[ $exit_code -eq 0 ]]; then
        success "Phase 1 completed successfully"
        return 0
    else
        error "Phase 1 failed or was cancelled"
        warn "Check logs for details: $LOG_DIR/aio_master.log"
        echo ""
        log "Returning to main menu..."
        sleep 2
        return 1
    fi
}

run_phase2() {
    log "Starting Phase 2: Comprehensive Hardening"
    
    # Check if Phase 1 was run
    if [[ ! -f "$LOG_DIR/.phase1_complete" ]]; then
        warn "Phase 1 has not been run yet"
        if ! prompt_yes_no "Run Phase 2 anyway? (not recommended)"; then
            return 1
        fi
    fi
    
    if [[ ! -f "$SCRIPT_DIR/phase2_main.sh" ]]; then
        error "Phase 2 script not found: $SCRIPT_DIR/phase2_main.sh"
        return 1
    fi
    
    # Temporarily disable exit on error for this call
    set +e
    "$SCRIPT_DIR/phase2_main.sh"
    local exit_code=$?
    set -e
    
    if [[ $exit_code -eq 0 ]]; then
        success "Phase 2 completed successfully"
        return 0
    else
        error "Phase 2 failed or was cancelled"
        warn "Check logs for details: $LOG_DIR/aio_master.log"
        echo ""
        log "Returning to main menu..."
        sleep 2
        return 1
    fi
}

run_phase3() {
    log "Starting Phase 3: External Tools & Utilities"
    
    # Check if Phase 2 was run
    if [[ ! -f "$LOG_DIR/.phase2_complete" ]]; then
        warn "Phase 2 has not been run yet"
        warn "Phase 3 works best after Phase 2 hardening"
        if ! prompt_yes_no "Run Phase 3 anyway?"; then
            return 1
        fi
    fi
    
    if [[ ! -f "$SCRIPT_DIR/phase3_main.sh" ]]; then
        error "Phase 3 script not found: $SCRIPT_DIR/phase3_main.sh"
        return 1
    fi
    
    # Temporarily disable exit on error for this call
    set +e
    "$SCRIPT_DIR/phase3_main.sh"
    local exit_code=$?
    set -e
    
    if [[ $exit_code -eq 0 ]]; then
        success "Phase 3 completed successfully"
        return 0
    else
        error "Phase 3 failed or was cancelled"
        warn "Check logs for details: $LOG_DIR/aio_master.log"
        echo ""
        log "Returning to main menu..."
        sleep 2
        return 1
    fi
}

run_all_phases() {
    log "Running all phases sequentially..."
    echo ""
    
    # Phase 1
    if [[ ! -f "$LOG_DIR/.phase1_complete" ]]; then
        log "═══ Starting Phase 1 ═══"
        run_phase1 || return 1
        echo ""
    else
        log "Phase 1 already completed (skipping)"
        echo ""
    fi
    
    # Phase 2
    if [[ ! -f "$LOG_DIR/.phase2_complete" ]]; then
        log "═══ Starting Phase 2 ═══"
        run_phase2 || return 1
        echo ""
    else
        log "Phase 2 already completed (skipping)"
        echo ""
    fi
    
    # Phase 3
    if [[ ! -f "$LOG_DIR/.phase3_complete" ]]; then
        log "═══ Starting Phase 3 ═══"
        run_phase3 || return 1
        echo ""
    else
        log "Phase 3 already completed (skipping)"
        echo ""
    fi
    
    success "All phases completed!"
}

quick_actions_menu() {
    while true; do
        echo ""
        echo "════════════════════════════════════════════════════════════"
        echo " QUICK ACTIONS"
        echo "════════════════════════════════════════════════════════════"
        echo ""
        echo "  1. Verify Hardening Status"
        echo "  2. Check Service Health"
        echo "  3. View Red Flags (last hour)"
        echo "  4. View Logs"
        echo "  5. Run Comprehensive Backup"
        echo "  6. Run Port Enumeration"
        echo "  7. Run Service Enumeration"
        echo "  8. Run User Enumeration"
        echo "  9. Back to Main Menu"
        echo ""
        
        read -r -p "Selection [1-9]: " action_choice
        
        case "$action_choice" in
            1)
                if command -v aio-verify >/dev/null 2>&1; then
                    aio-verify
                else
                    warn "aio-verify not installed. Run Phase 2 first."
                fi
                ;;
            2)
                if command -v aio-check-services >/dev/null 2>&1; then
                    aio-check-services
                else
                    warn "aio-check-services not installed. Run Phase 2 first."
                fi
                ;;
            3)
                if command -v aio-redflags >/dev/null 2>&1; then
                    aio-redflags --last-hour
                else
                    warn "aio-redflags not installed. Run Phase 2 first."
                fi
                ;;
            4)
                echo ""
                echo "Recent log entries:"
                tail -30 "$LOG_DIR/aio_master.log" 2>/dev/null || echo "No logs found"
                ;;
            5)
                if command -v aio-backup-all >/dev/null 2>&1; then
                    echo ""
                    warn "This will backup configs, databases, and web content."
                    if prompt_yes_no "Run comprehensive backup now?"; then
                        aio-backup-all
                    fi
                else
                    warn "aio-backup-all not installed. Run Phase 3 first."
                fi
                ;;
            6)
                if command -v aio-enum-ports >/dev/null 2>&1; then
                    aio-enum-ports
                else
                    warn "aio-enum-ports not installed. Run Phase 2 first."
                fi
                ;;
            7)
                if command -v aio-enum-services >/dev/null 2>&1; then
                    aio-enum-services
                else
                    warn "aio-enum-services not installed. Run Phase 2 first."
                fi
                ;;
            8)
                if command -v aio-enum-users >/dev/null 2>&1; then
                    aio-enum-users
                else
                    warn "aio-enum-users not installed. Run Phase 2 first."
                fi
                ;;
            9)
                return 0
                ;;
            *)
                warn "Invalid selection"
                ;;
        esac
        
        echo ""
        read -r -p "Press Enter to continue..."
    done
}

main_menu() {
    while true; do
        show_banner
        show_menu
        
        read -r -p "Selection [1-6]: " choice
        
        case "$choice" in
            1)
                echo ""
                run_phase1 || true
                echo ""
                read -r -p "Press Enter to continue..."
                ;;
            2)
                echo ""
                run_phase2 || true
                echo ""
                read -r -p "Press Enter to continue..."
                ;;
            3)
                echo ""
                run_phase3 || true
                echo ""
                read -r -p "Press Enter to continue..."
                ;;
            4)
                echo ""
                if prompt_yes_no "Run all phases sequentially?"; then
                    run_all_phases || true
                fi
                echo ""
                read -r -p "Press Enter to continue..."
                ;;
            5)
                quick_actions_menu
                ;;
            6)
                echo ""
                log "Exiting AIO Hardening Script"
                
                # Calculate total time
                ELAPSED=$((SECONDS - START_TIME))
                MINUTES=$((ELAPSED / 60))
                SECS=$((ELAPSED % 60))
                
                echo ""
                echo "Session duration: ${MINUTES}m ${SECS}s"
                echo "Logs available at: $LOG_DIR/"
                echo ""
                exit 0
                ;;
            *)
                warn "Invalid selection. Please choose 1-6."
                sleep 1
                ;;
        esac
    done
}

# Pre-main checks
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "ERROR: AIO Hardening Script must be run as root"
    echo "Usage: sudo $0"
    exit 1
fi

# Handle command line arguments
case "${1:-}" in
    --phase1)
        run_phase1
        exit $?
        ;;
    --phase2)
        run_phase2
        exit $?
        ;;
    --phase3)
        run_phase3
        exit $?
        ;;
    --all)
        run_all_phases
        exit $?
        ;;
    --help|-h)
        echo "Usage: sudo $0 [option]"
        echo ""
        echo "Options:"
        echo "  (no option)    Interactive menu"
        echo "  --phase1       Run Phase 1 only"
        echo "  --phase2       Run Phase 2 only"
        echo "  --phase3       Run Phase 3 only"
        echo "  --all          Run all phases sequentially"
        echo "  --help         Show this help"
        exit 0
        ;;
    "")
        # No arguments, run interactive menu
        main_menu
        ;;
    *)
        echo "Unknown option: $1"
        echo "Run with --help for usage"
        exit 1
        ;;
esac
