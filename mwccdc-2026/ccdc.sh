#!/usr/bin/env bash
# ccdc.sh -- master launcher for the Linux kit.     sudo bash ccdc.sh
#   sudo bash ccdc.sh --recon    read-only: inventory, backup, red-flag scan, then stop (no system changes)
#   sudo bash ccdc.sh --dry-run  walk every phase and PRINT what it would do, changing nothing
# Flow: detect -> inventory/backup/recon -> accounts -> packages -> web -> ssh -> firewall -> baseline/monitor
# Asks before every change; Enter accepts the default shown ([Y/n] = yes, [y/N] = no). Logs: /root/ccdc-logs/<time>/
# Keep this file in the same folder as the other kit scripts.
export PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
D=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "$1" in -h|--help) sed -n '2,6p' "$0"; exit 0;; esac
[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo bash $0"; exit 1; }
[ -t 0 ] || { echo "ccdc.sh needs a terminal (it asks before every change). Run it directly, not piped."; exit 1; }
RECON=0; DRY=0
case "$1" in --recon) RECON=1;; --dry-run|--dry) DRY=1;; esac
export DRY
for f in inventory backup users persistence pkgcheck harden firewall baseline web-harden services splunk; do
  [ -f "$D/$f.sh" ] || { echo "missing $f.sh next to ccdc.sh"; exit 1; }; done
LOGDIR=/root/ccdc-logs/$(date +%m%d-%H%M); mkdir -p "$LOGDIR" || exit 1; chmod 700 /root/ccdc-logs "$LOGDIR"
if [ -t 1 ]; then B=$'\e[1m'; Y=$'\e[33m'; G=$'\e[32m'; Z=$'\e[0m'; else B=; Y=; G=; Z=; fi
exec 3<&0            # fd 3 = the real terminal, so prompts can't be eaten by a command reading stdin

# ---------- helpers ----------
say(){  echo; echo "${B}== $* ==${Z}"; }
warn(){ echo "${Y}! $*${Z}"; }
ok(){   echo "${G}[ok] $*${Z}"; }
yn(){ # yn "question" default(y|n); EOF/closed stdin counts as NO
  local d=${2:-n} p a; [ "$d" = y ] && p="[Y/n]" || p="[y/N]"
  read -r -u 3 -p "$1 $p " a || { echo; return 1; }; a=${a:-$d}; [[ $a =~ ^[yY]$ ]]; }
val(){ local v; read -r -u 3 -p "$1 [$2]: " v || v=""; echo "${v:-$2}"; }
pause(){ read -r -u 3 -p "$1" _ || true; }
run(){   local n=$1; shift; "$@" 2>&1 | tee -a "$LOGDIR/$n.log"; return "${PIPESTATUS[0]}"; }
quiet(){ local n=$1; shift; if "$@" >"$LOGDIR/$n.log" 2>&1; then ok "$n -> $LOGDIR/$n.log"
         else warn "$n had errors (exit $?) -- see $LOGDIR/$n.log"; tail -3 "$LOGDIR/$n.log" | sed 's/^/    /'; fi; }
listeners(){ ss -${1}ln 2>/dev/null | awk 'NR>1{for(i=1;i<=NF;i++) if($i ~ /:[0-9]+$/){print $i; break}}' | grep -vE '^(127\.|\[::1\]|\[::ffff:127\.|::1)' | sed 's/.*://' | grep -E '^[0-9]+$' | sort -nu | tr '\n' ' '; }
has(){ case " $LP_TCP " in *" $1 "*) return 0;; esac; return 1; }
anyport(){ local p; for p; do has "$p" && return 0; done; return 1; }
sect(){ awk -v h="$1" 'index($0,"===== " h){f=1;next} /^=====/{f=0} f && NF' "$LOGDIR/persistence.log" 2>/dev/null; }

# ---------- MWCCDC 2026 Invitational host table (from the team pack; verify on the day) ----------
# Internal 172.20.240.x behind the Palo Alto. Public = 172.25.(20+team#).x
profile(){ case "$1" in
  10)  echo "Rocky Ecom|Rocky Linux 9|E-Commerce web (HTTP/HTTPS)";;
  15)  echo "Ubuntu Email|Ubuntu 22.04|Mail: SMTP/POP3/IMAP/webmail";;
  20)  echo "Debian Splunk|Debian 12 + Splunk 10.0.2|Splunk query + mgmt 8089, fwd 9997";;
  100) echo "2022 AD|Windows Server 2022|AD/DNS/WinRM -- not a Linux box";;
  120) echo "2019 MSSQL|Windows Server 2019|MSSQL/SMB/RDP -- not a Linux box";;
  200) echo "Palo Alto mgmt|PAN-OS 11.0.2|FIREWALL WEB UI -- do not run this kit here";;
  254) echo "Palo Alto inside|PAN-OS 11.0.2|FIREWALL -- do not run this kit here";;
esac; }

# ---------- detect ----------
. /etc/os-release 2>/dev/null; DISTRO=${PRETTY_NAME:-unknown}
if command -v apt-get >/dev/null; then PM=apt; elif command -v dnf >/dev/null; then PM=dnf; elif command -v yum >/dev/null; then PM=yum; else PM=none; fi
ME=${SUDO_USER:-$(logname 2>/dev/null || echo root)}; SRC=${SSH_CLIENT%% *}; ADMIN=""; SKIP=""
command -v ss >/dev/null || warn "'ss' not found -- port detection will be blank (install iproute2/iproute)"
LP_TCP=$(listeners t); LP_UDP=$(listeners u)
roles=""
anyport 80 443 8080 && roles="$roles web"; anyport 25 110 143 993 995 && roles="$roles mail"
anyport 8000 8089 9997 && roles="$roles splunk"; anyport 3306 5432 && roles="$roles db"
anyport 53 && roles="$roles dns"; anyport 21 && roles="$roles ftp"; anyport 445 139 && roles="$roles smb"
WEBSVC=0; if command -v apache2ctl >/dev/null || command -v httpd >/dev/null; then WEBSVC=1; fi

echo "${B}CCDC Linux kit${Z}  host=$(hostname)  os=$DISTRO  pkg=$PM  firewalld=$(systemctl is-active firewalld 2>/dev/null)  selinux=$(getenforce 2>/dev/null || echo n/a)"
echo "listening tcp: ${LP_TCP:-none}   udp: ${LP_UDP:-none}"
echo "guessed roles:${roles:- none}   logs=$LOGDIR"
IP4=$(ip -4 -o addr show 2>/dev/null | grep -oE '172\.(20\.240|17\.0|16\.0)\.[0-9]+' | head -1)
OCT=$(echo "$IP4" | cut -d. -f4)
PROF=""; case "$IP4" in 172.20.240.*) PROF=$(profile "$OCT");; esac
if [ -n "$PROF" ]; then
  echo "${B}team pack says $IP4 = $(echo "$PROF" | tr '|' ' ')${Z}"
  case "$PROF" in *"do not run this kit"*) warn "This is the Palo Alto firewall. STOP -- use its web UI at https://172.20.240.200 (admin/Changeme123)."; exit 1;; esac
  case "$PROF" in *"not a Linux box"*) warn "Team pack says this address is a Windows box. Check you are on the right VM."; ;; esac
fi
case "$IP4" in 172.17.0.2) warn "This looks like the Kali workstation (172.17.0.2). It sits OUTSIDE the Palo Alto, on the VyOS wkst segment. It is a workstation, not a scored server -- rule 11 says workstations may not be re-tasked.";; esac
[ "$DRY" = 1 ] && warn "DRY RUN: every phase will print what it would do and change nothing."
[ "$RECON" = 1 ] && warn "RECON mode: nothing on the system will be changed."

# ---------- phases ----------
highlights(){
  say "RED FLAGS (quick checks; details in $LOGDIR)"
  local n=0 t
  t=$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd); [ -n "$t" ] && { warn "extra UID 0 accounts: $t"; n=1; }
  t=$(awk -F: '$2==""{print $1}' /etc/shadow 2>/dev/null); [ -n "$t" ] && { warn "EMPTY passwords: $t"; n=1; }
  t=$(grep -c . <<<"$(sect 'authorized_keys')"); [ "${t:-0}" -gt 0 ] && { warn "$t authorized_keys entries: review users-audit.log"; n=1; }
  grep -rqs NOPASSWD /etc/sudoers /etc/sudoers.d && { warn "NOPASSWD sudo entries present"; n=1; }
  [ -s /etc/ld.so.preload ] && { warn "/etc/ld.so.preload is non-empty (rootkit sign)"; n=1; }
  for h in "Possible webshells" "Executables in tmp-ish dirs" "Shell rc files w/ suspicious cmds" "Odd processes"; do
    t=$(sect "$h" | head -5); [ -n "$t" ] && { warn "$h:"; echo "$t" | sed 's/^/    /'; n=1; }; done
  t=$(grep -E ' /(usr/)?(s?bin|lib(64)?)/' "$LOGDIR/pkg-verify.log" 2>/dev/null | head -8)
  [ -n "$t" ] && { warn "system binaries/libs differ from their package (possible tampering; full list in pkg-verify.log):"; echo "$t" | sed 's/^/    /'; n=1; }
  if [ -s "$LOGDIR/splunk.log" ]; then
    t=$(grep -E '^\s*!!' "$LOGDIR/splunk.log" | head -6)
    [ -n "$t" ] && { warn "Splunk / log forwarding problems (full detail in splunk.log):"; echo "$t" | sed 's/^/  /'; n=1; }
  fi
  [ "$n" = 0 ] && ok "nothing obvious. Still read the logs."
}
phase_recon(){
  say "INVENTORY + BACKUP + RECON (read-only, a few minutes)"
  (cd "$LOGDIR" && bash "$D/inventory.sh" >/dev/null 2>&1) && ok "inventory -> $LOGDIR"
  quiet backup bash "$D/backup.sh"
  quiet users-audit bash "$D/users.sh" audit
  quiet persistence bash "$D/persistence.sh" 120
  quiet pkg-verify bash "$D/pkgcheck.sh" verify
  quiet pkg-unowned bash "$D/pkgcheck.sh" unowned
  quiet splunk bash "$D/splunk.sh" check
  highlights
}
phase_accounts(){
  if [ "$DRY" = 1 ]; then say "ACCOUNTS (dry run: skipped -- this phase changes passwords/packages/config)"; return 0; fi
  say "ACCOUNTS"
  local logins targets u
  logins=$(getent passwd | awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)$/ {print $1}' | tr '\n' ' ')
  echo "Login-capable accounts: $logins"
  warn "PACKET RULE: password changes are submitted through the SCORING ENGINE (https://quotient.ccdc.events),"
  warn "NOT through tickets. Rotate first, then submit the change there, or the service check fails."
  warn "If you are not ready to submit them, SKIP the scoring/service accounts for now."
  SKIP=$(val "Accounts to SKIP when rotating (space-separated)" "$SKIP")
  if yn "Create a new sudo admin account first?" y; then
    ADMIN=$(val "Admin username" "teamadmin")
    run users-newadmin bash "$D/users.sh" newadmin "$ADMIN" || ADMIN=""
    if [ -n "$ADMIN" ]; then
      bash "$D/users.sh" reveal <&3            # not logged: contains passwords
      if su - "$ADMIN" -c 'sudo -n true' 2>/dev/null || su - "$ADMIN" -c 'sudo -v' <&3; then ok "$ADMIN can use sudo"
      else warn "could not verify sudo for $ADMIN -- fix that BEFORE locking root"; fi
    fi
  fi
  targets=""; for u in $(getent passwd | awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)$/ {print $1}'); do
    case " $SKIP " in *" $u "*) ;; *) targets="$targets $u";; esac; done
  echo "Would rotate:$targets"
  warn "This includes YOUR login ($ME). The reveal step right after shows the new passwords -- write them down there and then."
  if [ -z "$(echo $SKIP)" ]; then
    warn "You named NO accounts to skip, so EVERY account above gets a new password --"
    warn "including any the scoring engine logs in with. Those checks fail until you"
    warn "submit the new passwords at https://quotient.ccdc.events"
    yn "Are you sure you want to rotate ALL of them?" n || { echo "skipping password rotation."; return 0; }
  fi
  if yn "Rotate passwords for these accounts now?" n; then
    run users-rotate env CCDC_YES=1 SKIP="$SKIP" bash "$D/users.sh" rotate
    bash "$D/users.sh" reveal <&3
  fi
  if [ -n "$ADMIN" ] && yn "Lock root's password? (sudo keeps working; only do this if the sudo test above passed)" n; then
    run users-lockroot env CCDC_YES=1 bash "$D/users.sh" lock root; fi
  if yn "Move ALL authorized_keys aside? (kills key-based logins incl. yours if you use keys)" n; then
    run users-keys bash "$D/users.sh" keys; fi
}
phase_packages(){
  if [ "$DRY" = 1 ]; then say "PACKAGES (dry run: skipped -- this phase changes passwords/packages/config)"; return 0; fi
  say "PACKAGES"
  if [ "$PM" != none ] && yn "Apply package updates now? (can restart/break scored services; best done while outbound is open)" n; then
    case $PM in apt) run updates bash -c 'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y upgrade';;
                dnf|yum) run updates $PM -y upgrade;; esac
    [ -f /var/run/reboot-required ] && warn "a reboot is pending -- do NOT reboot mid-scoring without telling your team"
  fi
  if yn "Check shells + installed software against the OS defaults? (asks before EVERY reinstall/removal)" y; then
    run pkg-shells  bash "$D/pkgcheck.sh" shells <&3
    run pkg-extras  bash "$D/pkgcheck.sh" extras <&3; fi
}
phase_web(){
  [ "$WEBSVC" = 1 ] || return 0
  say "WEB SERVER"
  yn "Harden Apache + scan docroot for webshells? (config-tested, auto-removed if invalid)" y || return 0
  local dr; dr=$(val "Docroot" "/var/www/html")
  run web env DOCROOT="$dr" bash "$D/web-harden.sh" apply
  pause "Load the scored web page now to confirm it still works, then press Enter... "
}
phase_ssh(){
  say "SSH HARDENING"
  command -v sshd >/dev/null || { echo "no sshd here, skipping"; return 0; }
  yn "Harden sshd? (5 tries, no X11, 30s grace; config-tested with auto-restore)" y || return 0
  local pr=no lc=no cu=""
  if [ "$ME" = root ] && [ -z "$ADMIN" ]; then
    warn "You're root and made no other admin: disabling root SSH login would lock you out of NEW logins."
    yn "Disable root SSH login anyway?" n || pr=yes; fi
  # NO SSH user allow-list here, on purpose. SSH is a scored service and the scoring
  # engine logs in with accounts whose names you may not know yet. AllowUsers is
  # deny-by-default: anyone not listed fails silently, and the service check fails
  # with it. This is not something to decide at a prompt under time pressure.
  echo "  NOT setting an SSH user allow-list. The scoring engine logs in over SSH with"
  echo "  accounts you may not control, and a whitelist makes those logins fail."
  echo "  If you genuinely need one, do it by hand AFTER you have confirmed every"
  echo "  scoring username, and test a scored check immediately:"
  echo "      sudo ALLOW_USERS=\"you teamadmin scoreuser1 scoreuser2\" bash harden.sh"
  if yn "Restrict cron/at to root only?" n; then lc=yes; cu=$(val "Extra users allowed cron/at" ""); fi
  if [ "$DRY" = 1 ]; then echo "  [dry] would run harden.sh with PERMIT_ROOT=$pr LOCK_CRON=$lc (no allow-list)"; return 0; fi
  run ssh env PERMIT_ROOT=$pr LOCK_CRON=$lc CRON_USERS="$cu" bash "$D/harden.sh"
  warn "Open a NEW terminal and log in over SSH to confirm it works."
  pause "Press Enter once verified (or Ctrl-C to stop here)... "
}
phase_firewall(){
  say "FIREWALL"
  yn "Set a default-deny inbound firewall? (auto-reverts unless you confirm)" y || return 0
  if command -v docker >/dev/null && systemctl is-active --quiet docker 2>/dev/null; then
    warn "Docker is running; flushing iptables can break container networking."; yn "Continue anyway?" n || return 0; fi
  echo "Current listeners:"; ss -tulpn 2>/dev/null
  local sshp t at au mg fw=DROP a
  sshp=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}'); sshp=${sshp:-22}
  t=$(echo $LP_TCP | tr ' ' '\n' | grep -vx "$sshp" | tr '\n' ' ' | sed 's/ $//')
  warn "Defaults below = everything currently listening. REMOVE ports that aren't scored services (red team may have opened some)."
  case " $LP_TCP " in *" 9997 "*|*" 8089 "*|*" 8000 "*)
    warn "This box listens on a Splunk port. KEEP 9997 (forwarders in), 8000 (query check)"
    warn "and 8089 (SCORED management check). Dropping any of them breaks logging team-wide.";; esac
  at=$(val "Allowed inbound TCP ports (SSH $sshp is added automatically)" "$t")
  au=$(val "Allowed inbound UDP ports" "$(echo $LP_UDP | sed 's/ $//')")
  mg=""   # MWCCDC rule 9: public services must be reachable from ALL source IPs.
          # Source-IP filtering "may incur a penalty when detected" and knife-edge
          # access for the scoring engine is explicitly prohibited. No prompt here.
  echo "  NOT restricting any service by source IP. MWCCDC rule 9 requires public"
  echo "  services to be reachable from all source addresses, and filtering can draw"
  echo "  a penalty. (You may still block a specific IP that is attacking you.)"
  if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = 1 ]; then warn "This box forwards packets (router/NAT?): keeping FORWARD ACCEPT."; fw=ACCEPT; fi
  [ -z "$at$au" ] && at=$sshp
  run firewall env DRY=$DRY ALLOW_TCP="$at" ALLOW_UDP="$au" MGMT="$mg" SSH_PORT="$sshp" FORWARD=$fw ROLLBACK_SECS=300 bash "$D/firewall.sh" || { warn "firewall script failed; previous rules left in place"; return 0; }
  [ "$DRY" = 1 ] && return 0
  echo; warn "Open a SECOND session: test SSH and every scored service. You have ~5 minutes."
  warn "(SLA hits after 5 failed checks at 2-4 min each, so you have ~10 min of real slack. Do not dawdle.)"
  if read -r -u 3 -t 290 -p "Keep these rules? [y/N] (no answer = automatic rollback) " a && [[ $a =~ ^[yY]$ ]]; then
    kill "$(cat /run/ccdc-fw.pid 2>/dev/null)" 2>/dev/null
    run firewall-save bash "$D/firewall.sh" save; ok "firewall kept and saved"
  else echo; warn "Not confirmed: rules will roll back automatically."; fi
}
phase_splunk(){
  say "SPLUNK / LOG FORWARDING"
  echo "Every box must reach the indexer. If forwarders die, the Splunk Query check can"
  echo "fail AND you lose the evidence for incident reports (20% of the score)."
  if [ "$DRY" = 1 ]; then echo "  [dry] would run: splunk.sh check, then offer fix + watch"; return 0; fi
  run splunk-check bash "$D/splunk.sh" check
  if grep -qE '^\s*!!' "$LOGDIR/splunk-check.log" 2>/dev/null; then
    warn "Problems found above."
    yn "Try to repair log forwarding now? (asks before every change)" y \
      && run splunk-fix bash "$D/splunk.sh" fix <&3
  else
    ok "no forwarding problems detected"
  fi
  yn "Add Splunk to the watchdog so a dead forwarder gets restarted?" y \
    && run splunk-watch bash "$D/splunk.sh" watch
}
phase_services(){
  say "SCORED SERVICES"
  echo "The packet scores ~10 services every 2-4 minutes; an SLA hits after 5 failed checks."
  if [ "$DRY" = 1 ]; then echo "  [dry] would run: services.sh discover, then start the watchdog"; return 0; fi
  run services-discover bash "$D/services.sh" discover <&3
  warn "Edit /etc/ccdc/services.conf now: delete non-scored ports, fix any FIXME- unit names."
  pause "Press Enter when the watch list looks right... "
  run services-check bash "$D/services.sh" check
  if yn "Start the service watchdog? (restarts a dead scored service, max 3 times per 15 min)" y; then
    pkill -f "$D/services.sh watch" 2>/dev/null
    setsid nohup bash "$D/services.sh" watch 30 >/dev/null 2>&1 &
    ok "watchdog running. Log: /root/ccdc-logs/services.log | Stop: pkill -f 'services.sh watch'"
  fi
}
phase_baseline(){
  if [ "$DRY" = 1 ]; then say "BASELINE (dry run: skipped)"; return 0; fi
  say "BASELINE + MONITOR"
  run baseline bash "$D/baseline.sh" snap
  if yn "Start background change monitor? (appends to /root/ccdc-logs/alerts.log every 5 min)" y; then
    pkill -f "$D/baseline.sh log" 2>/dev/null
    setsid nohup nice -n 19 ionice -c3 bash "$D/baseline.sh" log 300 >/dev/null 2>&1 &
    ok "monitor running (low priority). Watch: tail -f /root/ccdc-logs/alerts.log | Stop: pkill -f 'baseline.sh log'"; fi
}
summary(){
  say "DONE"
  echo "Logs: $LOGDIR"
  echo "Splunk: 'bash $D/splunk.sh check' on EVERY box | 'splunk.sh indexer' on 172.20.240.20"
  echo "Next: 'bash $D/persistence.sh' periodically | 'bash $D/baseline.sh diff' for changes | 'bash $D/firewall.sh suggest' to re-check listeners"
  echo "Handwrite the new credentials and hand them to the black team per the rules. Never leave them on screen."
}

# ---------- main ----------
phase_recon
if [ -d /opt/vyatta ] || [ -d /config ] && [ -f /config/config.boot ]; then
  warn "This is the VyOS router. The kit's Linux hardening does NOT apply here."
  warn "Run recon/backup only, then see VYOS.md. REMEMBER: there are NO snapshots or"
  warn "scrubs in this environment -- if you break the router, there is no revert."
  quiet vyos bash "$D/vyos-backup.sh"
  summary; exit 0
fi
[ "$RECON" = 1 ] && { summary; exit 0; }
yn "Recon done. Continue to hardening?" y || { summary; exit 0; }
[ -n "$SRC" ] && warn "You're on SSH from $SRC. Keep this session open for the whole run; test NEW logins before closing it."
phase_accounts; phase_packages; phase_web; phase_ssh; phase_firewall; phase_splunk; phase_services; phase_baseline; summary
