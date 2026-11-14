#!/usr/bin/env bash
# vyos-backup.sh -- run ON the VyOS router (VyOS 1.4.0, user vyos) in a normal shell, NOT config mode.
# Read-only except for writing a backup directory. Backs up the config and lists persistence spots.
#   bash vyos-backup.sh
# MWCCDC: there are NO snapshots and NO scrubs in this environment. If you break the router you
# cannot revert it. Back up first, use 'commit-confirm', and test after every change.
case "$1" in -h|--help|help)
  awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0;; esac
d=$HOME/vyos-backup-$(date +%m%d-%H%M); mkdir -p "$d" || exit 1
cp -a /config "$d/config-dir" 2>/dev/null
OP=/opt/vyatta/bin/vyatta-op-cmd-wrapper
$OP show configuration commands > "$d/running-commands.txt" 2>/dev/null
$OP show configuration          > "$d/running-config.txt"   2>/dev/null
(cd "$d" && find . -type f -exec sha256sum {} + > SHA256SUMS 2>/dev/null)
echo "Backup in $d"
echo "Copy it OFF the router -- there is no snapshot to fall back on."
sec(){ echo; echo "===== $* ====="; }
sec "Boot-time scripts (classic persistence spot)"
ls -la /config/scripts /config/scripts/*.d 2>/dev/null
cat /config/scripts/vyos-postconfig-bootup.script 2>/dev/null
sec "Login users (anyone you did not create is red team)"
grep -E "system login user" "$d/running-commands.txt" 2>/dev/null
sec "SSH / service config"
grep -E "service ssh|service https|service snmp|service telnet" "$d/running-commands.txt" 2>/dev/null
sec "NAT rules -- the port forwards your scored services depend on"
grep -E "nat " "$d/running-commands.txt" 2>/dev/null
sec "Firewall rules"
grep -E "firewall " "$d/running-commands.txt" 2>/dev/null | head -40
sec "Routes (want STATIC only; default should be 0.0.0.0/0 via <gw>)"
$OP show ip route 2>/dev/null
sec "Interfaces (any you do not recognise?)"
$OP show interfaces 2>/dev/null
sec "Dynamic routing configured?"
grep -E "protocols (bgp|ospf|rip|isis)" "$d/running-commands.txt" 2>/dev/null \
  && echo "^^ dynamic routing present: justify it or remove it" || echo "none found -- good"
cat <<'EOT'

CHANGING THE VyOS PASSWORD (default is vyos:vyos -- change it)
  configure
  set system login user vyos authentication plaintext-password <newpass>
  commit-confirm      <- auto-reverts in 10 min unless you type 'confirm'
  confirm
  save

DO NOT firewall this router into a corner. It carries every scored service in and out,
and MWCCDC rule 9 forbids filtering public services by source IP.
EOT
exit 0
