#!/usr/bin/env bash
# Install RKHunter rootkit detection
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$SCRIPT_DIR/lib/logging.sh"
. "$SCRIPT_DIR/lib/detect.sh"

main() {
    log "[RKHUNTER] Installing RKHunter..."
    
    local pkg_mgr
    pkg_mgr=$(detect_package_manager)
    
    case "$pkg_mgr" in
        apt)
            apt-get update -qq
            apt-get install -y rkhunter
            ;;
        yum|dnf)
            $pkg_mgr install -y rkhunter
            ;;
        *)
            error "[RKHUNTER] Unsupported package manager"
            return 1
            ;;
    esac
    
    log "[RKHUNTER] Updating databases..."
    rkhunter --update || true
    rkhunter --propupd || true
    
    success "[RKHUNTER] Installed and updated"
    log "[RKHUNTER] Run scan: rkhunter --check --skip-keypress"
}

main "$@"
