#!/usr/bin/env bash
# modules/phase2/setup_monitoring.sh - Deploy active monitoring

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$SCRIPT_DIR/lib/logging.sh"
. "$SCRIPT_DIR/lib/prompts.sh"

REDFLAG_DIR="/var/log/redflags"

main() {
    log "[MONITORING] Deploying active monitoring scripts..."
    
    mkdir -p "$REDFLAG_DIR"
    chmod 700 "$REDFLAG_DIR"
    
    # Install monitoring scripts
    local monitors=(
        "process"
        "network"
        "file"
        "user"
        "cron"
    )
    
    for monitor in "${monitors[@]}"; do
        if [[ -f "$SCRIPT_DIR/monitors/monitor_${monitor}.sh" ]]; then
            cp "$SCRIPT_DIR/monitors/monitor_${monitor}.sh" /usr/local/bin/aio-monitor-${monitor}
            chmod +x /usr/local/bin/aio-monitor-${monitor}
            log "[MONITORING] Installed: aio-monitor-${monitor}"
        fi
    done
    
    # Create systemd services or cron jobs
    if command -v systemctl >/dev/null 2>&1; then
        setup_systemd_monitors
    else
        setup_cron_monitors
    fi
    
    success "[MONITORING] Active monitoring deployed to $REDFLAG_DIR/"
}

setup_systemd_monitors() {
    log "[MONITORING] Setting up systemd services..."
    
    # Process monitor service
    cat > /etc/systemd/system/aio-monitor-process.service << 'SERVICE'
[Unit]
Description=AIO Process Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/aio-monitor-process
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
SERVICE

    # Similar for other monitors
    systemctl daemon-reload
    systemctl enable aio-monitor-process.service 2>/dev/null || true
    systemctl start aio-monitor-process.service 2>/dev/null || true
    
    log "[MONITORING] Systemd services configured"
}

setup_cron_monitors() {
    log "[MONITORING] Setting up cron jobs..."
    
    # Add to crontab
    (crontab -l 2>/dev/null; echo "* * * * * /usr/local/bin/aio-monitor-process") | crontab -
    (crontab -l 2>/dev/null; echo "* * * * * /usr/local/bin/aio-monitor-network") | crontab -
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/aio-monitor-file") | crontab -
    
    log "[MONITORING] Cron jobs configured"
}

main "$@"
