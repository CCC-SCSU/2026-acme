#!/usr/bin/env bash
# Install all utility helper scripts
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$SCRIPT_DIR/lib/logging.sh"

main() {
    log "[UTILITIES] Installing utility scripts..."
    
    # Copy all utilities from utilities/ to /usr/local/bin/
    local count=0
    
    for util in "$SCRIPT_DIR/utilities/"*; do
        if [[ -f "$util" ]]; then
            local basename
            basename=$(basename "$util")
            cp "$util" "/usr/local/bin/$basename"
            chmod +x "/usr/local/bin/$basename"
            log "[UTILITIES] Installed: $basename"
            ((count++))
        fi
    done
    
    # Install additional Phase 3 utilities
    install_backup_utilities
    install_log_utilities
    install_misc_utilities
    
    success "[UTILITIES] Installed $count + additional utility scripts"
    log "[UTILITIES] All utilities available in /usr/local/bin/"
}

install_backup_utilities() {
    log "[UTILITIES] Installing backup utilities..."
    
    # Database backup
    cat > /usr/local/bin/aio-backup-db << 'DBBACKUP'
#!/usr/bin/env bash
# Backup databases
BACKUP_DIR="/var/backups/aio"
mkdir -p "$BACKUP_DIR"

echo "=== Database Backup ==="
echo "Timestamp: $(date)"

if command -v mysqldump >/dev/null 2>&1; then
    echo "Backing up MySQL/MariaDB..."
    mysqldump --all-databases > "$BACKUP_DIR/mysql_$(date +%Y%m%d_%H%M%S).sql"
fi

if command -v pg_dumpall >/dev/null 2>&1; then
    echo "Backing up PostgreSQL..."
    sudo -u postgres pg_dumpall > "$BACKUP_DIR/postgres_$(date +%Y%m%d_%H%M%S).sql"
fi

echo "Backups saved to: $BACKUP_DIR"
DBBACKUP

    # Web content backup
    cat > /usr/local/bin/aio-backup-web << 'WEBBACKUP'
#!/usr/bin/env bash
# Backup web content
BACKUP_DIR="/var/backups/aio"
mkdir -p "$BACKUP_DIR"

echo "=== Web Content Backup ==="

for webroot in /var/www /usr/share/nginx/html; do
    if [[ -d "$webroot" ]]; then
        echo "Backing up $webroot..."
        tar -czf "$BACKUP_DIR/web_$(date +%Y%m%d_%H%M%S).tar.gz" "$webroot"
        echo "Backup created"
    fi
done
WEBBACKUP

    # Config backup
    cat > /usr/local/bin/aio-backup-configs << 'CFGBACKUP'
#!/usr/bin/env bash
# Backup configuration files
BACKUP_DIR="/var/backups/aio/configs_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "=== Configuration Backup ==="

# Copy important configs
cp -r /etc/apache2 "$BACKUP_DIR/" 2>/dev/null || true
cp -r /etc/httpd "$BACKUP_DIR/" 2>/dev/null || true
cp -r /etc/nginx "$BACKUP_DIR/" 2>/dev/null || true
cp -r /etc/postfix "$BACKUP_DIR/" 2>/dev/null || true
cp -r /etc/dovecot "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/fstab "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/hosts "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/resolv.conf "$BACKUP_DIR/" 2>/dev/null || true

# Firewall
iptables-save > "$BACKUP_DIR/iptables.rules" 2>/dev/null || true
ufw status verbose > "$BACKUP_DIR/ufw.status" 2>/dev/null || true
firewall-cmd --list-all > "$BACKUP_DIR/firewalld.conf" 2>/dev/null || true

echo "Configs backed up to: $BACKUP_DIR"
CFGBACKUP

    chmod +x /usr/local/bin/aio-backup-{db,web,configs}
}

install_log_utilities() {
    log "[UTILITIES] Installing log utilities..."
    
    # Log checker
    cat > /usr/local/bin/aio-check-logs << 'LOGCHECK'
#!/usr/bin/env bash
# Check logs for suspicious activity
MINUTES="${1:-10}"

echo "=== Log Check (last $MINUTES minutes) ==="
echo ""

# Auth logs
if [[ -f /var/log/auth.log ]]; then
    echo "Failed logins:"
    grep "Failed password" /var/log/auth.log | tail -20
fi

# Apache/Nginx errors
for log in /var/log/apache2/error.log /var/log/httpd/error_log /var/log/nginx/error.log; do
    if [[ -f "$log" ]]; then
        echo ""
        echo "Web server errors ($log):"
        tail -20 "$log"
    fi
done

# Mail errors
if [[ -f /var/log/mail.log ]]; then
    echo ""
    echo "Mail errors:"
    grep -i "error\|fail\|reject" /var/log/mail.log | tail -20
fi
LOGCHECK

    chmod +x /usr/local/bin/aio-check-logs
}

install_misc_utilities() {
    log "[UTILITIES] Installing misc utilities..."
    
    # Show firewall
    cat > /usr/local/bin/aio-show-firewall << 'FWSHOW'
#!/usr/bin/env bash
# Display firewall rules
echo "=== Firewall Status ==="

if command -v ufw >/dev/null 2>&1; then
    echo "UFW:"
    ufw status verbose
elif command -v firewall-cmd >/dev/null 2>&1; then
    echo "firewalld:"
    firewall-cmd --list-all
else
    echo "iptables:"
    iptables -L -n -v
fi
FWSHOW

    # Show connections
    cat > /usr/local/bin/aio-show-connections << 'CONNSHOW'
#!/usr/bin/env bash
# Display network connections
MODE="${1:---all}"

echo "=== Network Connections ==="

case "$MODE" in
    --listening)
        echo "Listening ports:"
        ss -tulpn | grep LISTEN
        ;;
    --established)
        echo "Established connections:"
        ss -tupn state established
        ;;
    --external)
        echo "External connections (non-local):"
        ss -tupn | grep -v "127.0.0.1\|::1"
        ;;
    *)
        echo "All connections:"
        ss -tupan
        ;;
esac
CONNSHOW

    # System snapshot
    cat > /usr/local/bin/aio-snapshot << 'SNAPSHOT'
#!/usr/bin/env bash
# Take system snapshot
SNAPSHOT_DIR="/var/log/aio_hardening/snapshots/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$SNAPSHOT_DIR"

echo "Taking system snapshot..."

ps aux > "$SNAPSHOT_DIR/processes.txt"
ss -tupan > "$SNAPSHOT_DIR/network.txt"
awk -F: '{print $1":"$3}' /etc/passwd > "$SNAPSHOT_DIR/users.txt"
systemctl list-units --type=service > "$SNAPSHOT_DIR/services.txt" 2>/dev/null || true
dpkg -l > "$SNAPSHOT_DIR/packages.txt" 2>/dev/null || rpm -qa > "$SNAPSHOT_DIR/packages.txt" 2>/dev/null || true

echo "Snapshot saved to: $SNAPSHOT_DIR"
SNAPSHOT

    chmod +x /usr/local/bin/aio-show-{firewall,connections}
    chmod +x /usr/local/bin/aio-snapshot
}

main "$@"
