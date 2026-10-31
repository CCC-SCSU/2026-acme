#!/usr/bin/env bash
# modules/phase1/process_baseline.sh - Process baseline and cleanup

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=/dev/null
. "$SCRIPT_DIR/lib/logging.sh"

LOG_DIR="/var/log/aio_hardening"
BASELINE_FILE="$LOG_DIR/baseline_processes_$(date +%Y%m%d_%H%M%S).txt"

# Suspicious ports (common reverse shells)
SUSPICIOUS_PORTS=(4444 1337 31337 5555 6666 8080 3389)

main() {
    log "[PROCESS] Creating process baseline..."
    
    # Save current processes
    ps aux > "$BASELINE_FILE"
    log "[PROCESS] Baseline saved to: $BASELINE_FILE"
    
    # Kill processes on suspicious ports
    log "[PROCESS] Scanning for processes on suspicious ports..."
    local killed=0
    
    for port in "${SUSPICIOUS_PORTS[@]}"; do
        if command -v lsof >/dev/null 2>&1; then
            local pids
            pids=$(lsof -ti ":$port" 2>/dev/null || true)
            if [[ -n "$pids" ]]; then
                log "[PROCESS] Found process(es) on port $port: $pids"
                for pid in $pids; do
                    local pname
                    pname=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
                    log "[PROCESS] Killing PID $pid ($pname) on port $port"
                    kill -9 "$pid" 2>/dev/null || warn "[PROCESS] Could not kill PID $pid"
                    ((killed++)) || true
                done
            fi
        elif command -v ss >/dev/null 2>&1; then
            local pids
            pids=$(ss -lptn "sport = :$port" 2>/dev/null | awk '{print $6}' | grep -oP "pid=\K[0-9]+" || true)
            if [[ -n "$pids" ]]; then
                log "[PROCESS] Found process(es) on port $port via ss"
                for pid in $pids; do
                    log "[PROCESS] Killing PID $pid on port $port"
                    kill -9 "$pid" 2>/dev/null || warn "[PROCESS] Could not kill PID $pid"
                    ((killed++)) || true
                done
            fi
        fi
    done
    
    # Kill suspicious binaries in /tmp, /dev/shm
    log "[PROCESS] Checking for suspicious binaries in /tmp and /dev/shm..."
    for dir in /tmp /dev/shm; do
        if [[ -d "$dir" ]]; then
            while IFS= read -r -d '' file; do
                if [[ -x "$file" ]]; then
                    log "[PROCESS] Found executable in $dir: $file"
                    # Check if it's running
                    local pids
                    pids=$(pgrep -f "$file" 2>/dev/null || true)
                    if [[ -n "$pids" ]]; then
                        log "[PROCESS] Killing process(es) for: $file"
                        pkill -9 -f "$file" 2>/dev/null || warn "[PROCESS] Could not kill process"
                        ((killed++)) || true
                    fi
                    # Optionally delete the file
                    if prompt_yes_no "[PROCESS] Delete suspicious file $file?"; then
                        rm -f "$file" && log "[PROCESS] Deleted $file"
                    fi
                fi
            done < <(find "$dir" -type f -executable -print0 2>/dev/null)
        fi
    done
    
    if [[ $killed -gt 0 ]]; then
        success "[PROCESS] Killed $killed suspicious process(es)"
    else
        log "[PROCESS] No suspicious processes found"
    fi
    
    success "[PROCESS] Process baseline complete"
}

# Need prompts for this module
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=/dev/null
. "$SCRIPT_DIR/lib/prompts.sh"

main "$@"
