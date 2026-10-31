#!/usr/bin/env bash
# lib/logging.sh - Logging functions

LOG_DIR="/var/log/aio_hardening"
LOG_FILE="$LOG_DIR/aio_master.log"

# Ensure log directory exists
mkdir -p "$LOG_DIR" 2>/dev/null || true

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging function
log() {
    local timestamp
    timestamp=$(date '+%Y-%m-%dT%H:%M:%S%z')
    echo "[${timestamp}] [INFO] $*" | tee -a "$LOG_FILE"
}

# Warning function
warn() {
    local timestamp
    timestamp=$(date '+%Y-%m-%dT%H:%M:%S%z')
    echo -e "${YELLOW}[${timestamp}] [WARN] $*${NC}" | tee -a "$LOG_FILE"
}

# Error function
error() {
    local timestamp
    timestamp=$(date '+%Y-%m-%dT%H:%M:%S%z')
    echo -e "${RED}[${timestamp}] [ERROR] $*${NC}" | tee -a "$LOG_FILE" >&2
}

# Success function
success() {
    local timestamp
    timestamp=$(date '+%Y-%m-%dT%H:%M:%S%z')
    echo -e "${GREEN}[${timestamp}] [SUCCESS] $*${NC}" | tee -a "$LOG_FILE"
}

# Die function - log error and exit
die() {
    error "$*"
    exit 1
}

# Export functions
export -f log warn error success die
