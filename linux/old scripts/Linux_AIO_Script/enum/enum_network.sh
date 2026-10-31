#!/usr/bin/env bash
# Enumerate network connections
echo "=== Network Connections ==="
echo "Generated: $(date)"
echo ""

echo "Listening ports:"
ss -tulpn 2>/dev/null | grep LISTEN
echo ""

echo "Established connections:"
ss -tupn state established 2>/dev/null
