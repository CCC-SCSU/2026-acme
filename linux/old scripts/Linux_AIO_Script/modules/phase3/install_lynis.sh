#!/usr/bin/env bash
# Install Lynis security auditing tool
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$SCRIPT_DIR/lib/logging.sh"
. "$SCRIPT_DIR/lib/detect.sh"

main() {
    log "[LYNIS] Installing Lynis..."
    
    local pkg_mgr
    pkg_mgr=$(detect_package_manager)
    
    case "$pkg_mgr" in
        apt)
            apt-get update -qq
            apt-get install -y lynis
            ;;
        yum|dnf)
            $pkg_mgr install -y lynis
            ;;
        *)
            warn "[LYNIS] Not in repos, installing from GitHub..."
            cd /opt
            git clone https://github.com/CISOfy/lynis
            ln -s /opt/lynis/lynis /usr/local/bin/lynis
            ;;
    esac
    
    success "[LYNIS] Installed"
    log "[LYNIS] Run audit: lynis audit system"
}

main "$@"
