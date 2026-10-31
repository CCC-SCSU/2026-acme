#!/usr/bin/env bash
# Enumerate running services
echo "=== Running Services ==="
echo "Generated: $(date)"
echo ""

if command -v systemctl >/dev/null 2>&1; then
    systemctl list-units --type=service --state=running
else
    service --status-all 2>/dev/null
fi
