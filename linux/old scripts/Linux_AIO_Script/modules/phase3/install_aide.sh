#!/usr/bin/env bash
# Install and configure AIDE (File Integrity Monitoring)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$SCRIPT_DIR/lib/logging.sh"
. "$SCRIPT_DIR/lib/detect.sh"

main() {
    log "[AIDE] Installing AIDE File Integrity Monitoring..."
    
    local pkg_mgr
    pkg_mgr=$(detect_package_manager)
    
    case "$pkg_mgr" in
        apt)
            apt-get update -qq
            apt-get install -y aide aide-common
            ;;
        yum|dnf)
            $pkg_mgr install -y aide
            ;;
        *)
            error "[AIDE] Unsupported package manager"
            return 1
            ;;
    esac
    
    log "[AIDE] Initializing AIDE database (this may take a few minutes)..."
    aideinit || aide --init
    
    if [[ -f /var/lib/aide/aide.db.new ]]; then
        cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    elif [[ -f /var/lib/aide/aide.db.new.gz ]]; then
        cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    fi
    
    log "[AIDE] Setting up daily integrity checks..."
    cat > /etc/cron.daily/aide-check << 'CRON'
#!/bin/bash
/usr/bin/aide --check >> /var/log/redflags/aide_changes.log 2>&1
CRON
    chmod +x /etc/cron.daily/aide-check
    
    success "[AIDE] Installed and configured"
    log "[AIDE] First check: aide --check"
}

main "$@"
