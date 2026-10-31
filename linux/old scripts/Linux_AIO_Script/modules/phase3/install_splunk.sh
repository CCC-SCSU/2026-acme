#!/usr/bin/env bash
# Install Splunk Universal Forwarder with credential prompting
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$SCRIPT_DIR/lib/logging.sh"
. "$SCRIPT_DIR/lib/prompts.sh"

main() {
    log "[SPLUNK] Installing Splunk Universal Forwarder..."
    
    # Check if script exists
    if [[ ! -f "$SCRIPT_DIR/installers/linuxSplunkForwarderInstall.sh" ]]; then
        error "[SPLUNK] Splunk forwarder script not found!"
        error "[SPLUNK] Expected: $SCRIPT_DIR/installers/linuxSplunkForwarderInstall.sh"
        return 1
    fi
    
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║         SPLUNK UNIVERSAL FORWARDER SETUP                   ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    warn "You need Splunk indexer credentials from your team!"
    echo ""
    
    # Prompt for credentials (not logged anywhere!)
    local indexer_ip
    local admin_user
    local admin_pass
    
    read -r -p "Splunk Indexer IP Address: " indexer_ip
    read -r -p "Splunk Admin Username: " admin_user
    read -r -s -p "Splunk Admin Password: " admin_pass
    echo ""
    echo ""
    
    # Validate inputs
    if [[ -z "$indexer_ip" || -z "$admin_user" || -z "$admin_pass" ]]; then
        error "[SPLUNK] All fields are required!"
        return 1
    fi
    
    log "[SPLUNK] Running Splunk forwarder installation..."
    log "[SPLUNK] Indexer: $indexer_ip"
    log "[SPLUNK] Username: $admin_user"
    log "[SPLUNK] Password: (hidden - not logged)"
    
    # Run the script with credentials (not logged!)
    # Redirect stderr to hide password from logs
    if "$SCRIPT_DIR/installers/linuxSplunkForwarderInstall.sh" "$indexer_ip" "$admin_user" "$admin_pass" 2>&1 | grep -v "$admin_pass"; then
        success "[SPLUNK] Splunk Universal Forwarder installed successfully"
        log "[SPLUNK] Forwarder is sending to: $indexer_ip:9997"
        log "[SPLUNK] Check status: /opt/splunkforwarder/bin/splunk status"
    else
        error "[SPLUNK] Splunk installation failed"
        return 1
    fi
}

main "$@"
