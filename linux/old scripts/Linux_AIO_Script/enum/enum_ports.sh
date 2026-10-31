#!/usr/bin/env bash
# Enumerate listening ports
echo "=== Listening Ports ==="
echo "Generated: $(date)"
echo ""
ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null
