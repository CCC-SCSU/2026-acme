#!/usr/bin/env bash
# harden.sh -- Rocky Ecom (172.20.240.10, Rocky Linux 9)
#   sudo bash harden.sh          guided, asks before every change
#   sudo bash harden.sh dry      print the plan, change nothing
# Calls the tested kit scripts with this box's values. Nothing new or untested here.
K=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
[ -f "$K/ccdc.sh" ] || { echo "Kit not found. This folder must stay inside mwccdc-2026/."; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "run with sudo:  sudo bash harden.sh $*"; exit 1; }
TCP="80 443"; UDP=""
cat <<'EOT'
================================================================
 Rocky Ecom  --  172.20.240.10  --  Rocky Linux 9
 SCORED: HTTP (80), HTTPS (443), SSH, Ping. FTP may be here too -- CHECK.
EOT
sed -n '/^GOTCHAS/,/^END/p' "$(dirname "${BASH_SOURCE[0]}")/README.txt" | sed '1d;$d'
echo "================================================================"
[ "$1" = dry ] && { echo; echo "DRY RUN -- nothing will change."; exec bash "$K/go" d; }
read -r -p "Press Enter to start (Ctrl-C to stop)... " _ </dev/tty || exit 0

echo; echo "### 1/5  RECON + BACKUP (changes nothing)"
bash "$K/ccdc.sh" --recon </dev/tty
echo "  Copy the backup off this box:  scp -r /root/backup-* sysadmin@<wkst>:"

echo; echo "### 2/5  TRIPWIRES"
read -r -p "Arm the honeypot? [Y/n] " a </dev/tty
case "$a" in n|N) ;; *) bash "$K/honeypot.sh" arm;; esac

echo; echo "### 3/5  PASSWORDS"
echo "  Default everywhere is sysadmin / Changeme1! -- red team has the packet too."
echo "  Change it:        sudo sh $K/plan-b/2-pw.sh sysadmin"
echo "  Then SUBMIT it:   https://quotient.ccdc.events   (PCR tab, CSV: username,password)"
read -r -p "  Press Enter when submitted (or to skip)... " _ </dev/tty || true

echo; echo "### 4/5  SSH + SYSTEM HARDENING"
bash "$K/harden.sh" </dev/tty
bash "$K/rootssh.sh" check
read -r -p "  Block root over SSH? [y/N] " a </dev/tty
case "$a" in y|Y) bash "$K/rootssh.sh" disable </dev/tty;; esac

echo; echo "### 5/5  FIREWALL (default-deny inbound, auto-reverts in 5 min)"
echo "  What is actually listening:"
bash "$K/firewall.sh" suggest
echo
echo "  Suggested for this box -- TCP: 22 $TCP   UDP: ${UDP:-none}"
echo "  ICMP always stays open (Ping is scored, rule 12)."
read -r -p "  TCP ports to allow [$TCP]: " t </dev/tty; t=${t:-$TCP}
read -r -p "  UDP ports to allow [$UDP]: " u </dev/tty; u=${u:-$UDP}
if [ -z "$t$u" ]; then echo "  nothing specified -- skipping firewall"; else
  ALLOW_TCP="$t" ALLOW_UDP="$u" ROLLBACK_SECS=300 bash "$K/firewall.sh"
  echo; echo "  *** TEST EVERY SCORED SERVICE NOW from another window. ***"
  read -r -p "  Keep these rules? [y/N] " a </dev/tty
  case "$a" in y|Y) kill "$(cat /run/ccdc-fw.pid 2>/dev/null)" 2>/dev/null
                    bash "$K/firewall.sh" save;;
               *) echo "  not confirmed -- rules revert on their own";; esac
fi
echo
echo "DONE. Now start the watchdog:   sudo bash watch.sh"
