#!/usr/bin/env bash
# Enumerate installed packages
echo "=== Installed Packages ==="
echo "Generated: $(date)"
echo ""

if command -v dpkg >/dev/null 2>&1; then
    echo "Total packages: $(dpkg -l | grep -c '^ii')"
    echo ""
    echo "Recently installed (last 24h):"
    find /var/lib/dpkg/info -name "*.list" -mtime -1 2>/dev/null | sed 's/.*\/\(.*\)\.list/\1/'
elif command -v rpm >/dev/null 2>&1; then
    echo "Total packages: $(rpm -qa | wc -l)"
    echo ""
    echo "Recently installed (last 24h):"
    rpm -qa --last | head -20
fi
