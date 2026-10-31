#!/usr/bin/env bash
# Enumerate users
echo "=== User Accounts ==="
echo "Generated: $(date)"
echo ""

echo "UID 0 (root-equivalent):"
awk -F: '$3 == 0 {print "  " $1 " (UID: " $3 ")"}' /etc/passwd
echo ""

echo "Human users (UID >= 1000):"
awk -F: '$3 >= 1000 {print "  " $1 " (UID: " $3 ")"}' /etc/passwd
echo ""

echo "Sudo/Wheel members:"
getent group sudo wheel 2>/dev/null | cut -d: -f4
