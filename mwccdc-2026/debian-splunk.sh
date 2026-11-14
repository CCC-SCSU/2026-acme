#!/usr/bin/env bash
# debian-splunk.sh -- ordered runbook for YOUR box: Debian Splunk, 172.20.240.20.
#   sudo bash debian-splunk.sh          walk the whole sequence, pausing at each step
#   sudo bash debian-splunk.sh list     print the sequence without doing anything
# Each step tells you what it will do, then waits. 's' skips a step, 'q' quits.
# Ports baked in below are from the team pack -- VERIFY with 'firewall.sh suggest' on the day.
export PATH="/usr/sbin:/sbin:/usr/bin:/bin:$PATH"
D=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "$1" in -h|--help|help) sed -n '2,6p' "$0"; exit 0;; esac
# SCORED on this box: Splunk Query 8000, Splunk Management 8089, SSH 22, Ping (ICMP).
# ALSO REQUIRED: 9997 inbound (every other box forwards logs here), often 514/udp syslog.
TCP="8000 8089 9997"
UDP="514"
[ "$1" = list ] || { [ "$(id -u)" -eq 0 ] || { echo "run as root: sudo bash $0"; exit 1; }; }
[ "$1" = list ] || [ -t 0 ] || { echo "needs a terminal (it pauses at each step)"; exit 1; }
if [ -t 1 ]; then B=$'\e[1m'; Y=$'\e[33m'; G=$'\e[32m'; Z=$'\e[0m'; else B=; Y=; G=; Z=; fi
n=0
step(){ n=$((n+1)); echo; echo "${B}--- STEP $n: $1 ---${Z}"; shift; for l in "$@"; do echo "    $l"; done; }
go(){ [ "$1" = list ] && return 1; local a; read -r -p "    [Enter]=do it  s=skip  q=quit > " a </dev/tty || a=q
      case "$a" in s|S) echo "    skipped"; return 1;; q|Q) echo "    stopping here."; exit 0;; *) return 0;; esac; }
L=${1:-run}

step "RECON + BACKUP (changes nothing)" \
  "Inventory, full backup, account audit, persistence hunt, Splunk forwarding check." \
  "Read the RED FLAGS block it prints before you change anything." \
  "There are NO snapshots in this environment, so this backup is your only undo."
go "$L" && { bash "$D/ccdc.sh" --recon </dev/tty; echo
  echo "    ${Y}Copy the backup OFF this box now:${Z}"
  echo "      scp -r /root/backup-* sysadmin@<your-wkst>:"; }

step "ARM THE HONEYPOT (do this EARLY)" \
  "Tripwires on whoami / nc / netcat / socat / nmap / chattr / tcpdump." \
  "Nothing is blocked and nothing is killed automatically -- it only alerts." \
  "Then open a second pane and run:  sudo bash honeypot.sh watch"
go "$L" && { bash "$D/honeypot.sh" arm; echo
  read -r -p "    Plant decoy credential files too? [y/N] " a </dev/tty
  case "$a" in y|Y) bash "$D/honeypot.sh" bait;; esac; }

step "PASSWORDS" \
  "Default on every box is sysadmin / Changeme1! -- red team has the packet too." \
  "SKIP the Splunk admin account unless you are ready to submit it: the scored" \
  "Splunk Query check authenticates, so a changed Splunk password breaks it" \
  "until you submit via Quotient PCR (CSV: username,password)."
go "$L" && { bash "$D/users.sh" audit | head -20
  echo; echo "    Change the OS login now (one at a time is safest):"
  echo "      sudo sh plan-b/2-pw.sh sysadmin"
  echo "    Then submit it at https://quotient.ccdc.events  (PCR tab)"
  read -r -p "    Press Enter when submitted... " _ </dev/tty; }

step "SPLUNK -- YOU ARE THE INDEXER" \
  "Confirm 8000/8089/9997 are listening and that every other box is sending." \
  "A box missing from the connected list is not forwarding: go fix it there." \
  "Losing forwarders costs you the Splunk Query check AND your incident evidence."
go "$L" && { bash "$D/splunk.sh" check; echo; bash "$D/splunk.sh" indexer; echo
  bash "$D/splunk.sh" watch; }

step "SSH HARDENING + BLOCK ROOT" \
  "harden.sh: 5 auth tries, no X11, 30s grace. It does NOT set an AllowUsers" \
  "whitelist (that would lock out the scoring engine) and does NOT filter by" \
  "source IP (rule 9 penalises that). Then rootssh.sh blocks root specifically," \
  "after checking the auth logs to see whether anything legitimate uses root."
go "$L" && { bash "$D/harden.sh" </dev/tty; echo
  bash "$D/rootssh.sh" check; echo
  read -r -p "    Run 'rootssh.sh disable' now? [y/N] " a </dev/tty
  case "$a" in y|Y) bash "$D/rootssh.sh" disable </dev/tty;; esac; }

step "FIREWALL (default-deny inbound, auto-reverts in 5 min)" \
  "Allowing TCP: 22 $TCP   UDP: $UDP" \
  "ICMP stays open -- Ping is scored and rule 12 says maintain it." \
  "9997 MUST stay open or every other box stops logging to you." \
  "Outbound stays fully open. Test from a SECOND session before confirming."
go "$L" && { echo "    First, what is ACTUALLY listening:"; bash "$D/firewall.sh" suggest
  echo; read -r -p "    TCP ports to allow [$TCP]: " t </dev/tty; t=${t:-$TCP}
  read -r -p "    UDP ports to allow [$UDP]: " u </dev/tty; u=${u:-$UDP}
  ALLOW_TCP="$t" ALLOW_UDP="$u" ROLLBACK_SECS=300 bash "$D/firewall.sh"
  echo; echo "    ${Y}TEST NOW from another window: ssh in, load http://172.20.240.20:8000${Z}"
  read -r -p "    Keep these rules? [y/N] " a </dev/tty
  case "$a" in y|Y) kill "$(cat /run/ccdc-fw.pid 2>/dev/null)" 2>/dev/null
                    bash "$D/firewall.sh" save;;
                 *) echo "    not confirmed -- rules will revert on their own";; esac; }

step "WATCHDOG + BASELINE" \
  "services.sh restarts a scored service if it dies (max 3 per 15 min)." \
  "baseline.sh records the box's state so you can diff it later."
go "$L" && { bash "$D/services.sh" discover </dev/tty
  echo "    ${Y}Edit the watch list: remove non-scored ports, fix FIXME- names${Z}"
  echo "      sudo nano /etc/ccdc/services.conf"
  read -r -p "    Press Enter when it looks right... " _ </dev/tty
  bash "$D/services.sh" check
  pkill -f "$D/services.sh watch" 2>/dev/null
  setsid nohup bash "$D/services.sh" watch 30 >/dev/null 2>&1 &
  bash "$D/baseline.sh" snap
  echo "    ${G}watchdog running${Z} -- log: /root/ccdc-logs/services.log"; }

[ "$L" = list ] && exit 0
cat <<EOT

${B}=== SET UP, NOW RUN THE LOOP ===${Z}
Every 15 minutes:
  sudo bash $D/services.sh check        scored services still up?
  sudo bash $D/baseline.sh diff         what changed?
  sudo bash $D/splunk.sh indexer        is every box still forwarding?
  sudo bash $D/honeypot.sh alerts       anyone tripped a wire?

Keep running in panes:
  sudo bash $D/honeypot.sh watch        live tripwire alerts
  tail -f /root/ccdc-logs/services.log  watchdog activity

Write findings down as you go -- incident response is 20% of the score:
  echo "\$(date '+%H:%M') <what you found, source IP>" >> /root/incidents.txt

At the end:
  sudo bash $D/cleanup.sh
EOT
