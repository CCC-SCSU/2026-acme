#!/usr/bin/env bash
# Install ClamAV antivirus
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$SCRIPT_DIR/lib/logging.sh"
. "$SCRIPT_DIR/lib/detect.sh"

main() {
    log "[CLAMAV] Installing ClamAV..."
    
    local pkg_mgr
    pkg_mgr=$(detect_package_manager)
    
    # Install without recommended packages to avoid pulling in mail servers
    case "$pkg_mgr" in
        apt)
            apt-get update -qq
            apt-get install -y --no-install-recommends clamav clamav-freshclam
            ;;
        yum|dnf)
            $pkg_mgr install -y --setopt=install_weak_deps=False clamav clamav-update
            ;;
        *)
            error "[CLAMAV] Unsupported package manager"
            return 1
            ;;
    esac
    
    log "[CLAMAV] Updating virus definitions..."
    systemctl stop clamav-freshclam 2>/dev/null || true
    freshclam || true
    systemctl start clamav-freshclam 2>/dev/null || true
    
    log "[CLAMAV] Configuring daily scans..."
    cat > /etc/cron.daily/clamav-scan << '"'"'CLAM'"'"'
#!/bin/bash
clamscan -r -i /tmp /var/tmp /home >> /var/log/redflags/clamav_alerts.log 2>&1
CLAM
    chmod +x /etc/cron.daily/clamav-scan
    
    success "[CLAMAV] Installed and configured"
    log "[CLAMAV] Manual scan: clamscan -r /"
}

main "$@"
