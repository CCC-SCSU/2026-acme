#!/usr/bin/env bash
# modules/phase2/install_enum_tools.sh - Install enumeration tools

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$SCRIPT_DIR/lib/logging.sh"

main() {
    log "[ENUM] Installing enumeration tools..."
    
    # Install all enum tools to /usr/local/bin
    local tools=(
        "ports"
        "services"
        "users"
        "network"
        "packages"
        "persistence"
    )
    
    for tool in "${tools[@]}"; do
        if [[ -f "$SCRIPT_DIR/enum/enum_${tool}.sh" ]]; then
            cp "$SCRIPT_DIR/enum/enum_${tool}.sh" /usr/local/bin/aio-enum-${tool}
            chmod +x /usr/local/bin/aio-enum-${tool}
            log "[ENUM] Installed: aio-enum-${tool}"
        fi
    done
    
    success "[ENUM] All enumeration tools installed"
    log "[ENUM] Usage: aio-enum-ports, aio-enum-services, etc."
}

main "$@"
