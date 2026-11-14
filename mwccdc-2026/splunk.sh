#!/usr/bin/env bash
# splunk.sh -- make sure this box is talking to Splunk, both directions.
#   sudo bash splunk.sh check      READ ONLY. What is installed, running, forwarding where.
#   sudo bash splunk.sh indexer    READ ONLY. Run ON the Splunk box: who is reporting in?
#   sudo bash splunk.sh fix        Repair forwarding on this box (asks before every change).
#   sudo bash splunk.sh watch      Add Splunk's own processes to the services.sh watch list.
# Env: INDEXER=172.20.240.20   the Splunk box      RPORT=9997   receiving port
#      SPLUNK_USER=admin       only needed by 'fix'
# The read-only modes need NO Splunk password: they read config files, systemctl and ss.
# WHY THIS MATTERS: the scored "Splunk Query" check searches for specific CONTENT. If the
# forwarders on your other boxes die, that search can come back empty and the SPLUNK box
# fails its check. Incident response is 20% of the score and runs on these logs.
export PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
case "$1" in -h|--help|help)
  awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0;; esac
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
INDEXER=${INDEXER:-172.20.240.20}
RPORT=${RPORT:-9997}
ask(){ local a; read -r -p "$1 [y/N] " a || return 1; [ "$a" = y ] || [ "$a" = Y ]; }
# Who owns/runs this Splunk. Driving the CLI as root when it is installed to run as
# another user gets refused ("Running Splunk Enterprise as root is deprecated...").
splunk_user(){
  local u
  u=$(ps -o user= -p "$(pgrep -x splunkd 2>/dev/null | head -1)" 2>/dev/null | tr -d ' ')
  [ -n "$u" ] || u=$(stat -c '%U' "${HOME_DIR:-/opt/splunk}" 2>/dev/null)
  echo "${u:-root}"
}
# run the Splunk CLI as its owning user (no-op indirection when that is root)
as_splunk(){ local u=$1; shift
  if [ "$u" = root ] || [ "$u" = "$(id -un)" ]; then "$@"
  else su -s /bin/sh -c "$(printf '%s ' "$@")" "$u"; fi; }
sec(){ echo; echo "===== $* ====="; }
have(){ command -v "$1" >/dev/null 2>&1; }

# ---- locate whichever Splunk is here ----
UF=""; EN=""
for d in /opt/splunkforwarder /opt/SplunkForwarder /usr/local/splunkforwarder; do
  [ -x "$d/bin/splunk" ] && { UF=$d; break; }; done
for d in /opt/splunk /usr/local/splunk; do
  [ -x "$d/bin/splunk" ] && { EN=$d; break; }; done
HOME_DIR=${UF:-$EN}
ROLE=none; [ -n "$UF" ] && ROLE=forwarder; [ -n "$EN" ] && ROLE=indexer
[ -n "$UF" ] && [ -n "$EN" ] && ROLE="both"

# ---- find its service unit, whatever it is called ----
# How Splunk is managed on THIS box. The answer depends on how it was installed,
# not on the distro, so it varies between a practice VM and the real thing.
# Returns one of:  systemd:<unit>   initd:<name>   cli:<splunk binary>   (or nothing)
svc_kind(){
  local u
  for u in SplunkForwarder Splunkd splunk splunkd splunk-enterprise SplunkForwarder.service; do
    systemctl cat "${u%.service}.service" >/dev/null 2>&1 && { echo "systemd:${u%.service}.service"; return 0; }; done
  u=$(systemctl list-units --type=service --all --no-legend 2>/dev/null \
      | awk '{print $1}' | grep -iE '^splunk' | head -1)
  [ -n "$u" ] && { echo "systemd:$u"; return 0; }
  for u in splunk splunkd SplunkForwarder; do
    [ -x "/etc/init.d/$u" ] && { echo "initd:$u"; return 0; }; done
  # last resort: Splunk's own binary can always start/stop/restart itself
  [ -n "$HOME_DIR" ] && [ -x "$HOME_DIR/bin/splunk" ] && { echo "cli:$HOME_DIR/bin/splunk"; return 0; }
  return 1
}
# back-compat: callers that just want a printable name
unit_name(){ local k; k=$(svc_kind) || return 1; echo "${k#*:}"; }
svc_active(){ local k=$1
  case "$k" in
    systemd:*) systemctl is-active --quiet "${k#systemd:}";;
    initd:*)   "/etc/init.d/${k#initd:}" status >/dev/null 2>&1;;
    cli:*)     "${k#cli:}" status 2>/dev/null | grep -qi 'is running';;
    *) return 1;;
  esac; }
svc_do(){ local k=$1 act=$2
  case "$k" in
    systemd:*) systemctl "$act" "${k#systemd:}";;
    initd:*)   "/etc/init.d/${k#initd:}" "$act";;
    cli:*)     [ "$act" = start ] && "${k#cli:}" start --accept-license --answer-yes --no-prompt \
                 || "${k#cli:}" "$act";;
    *) return 1;;
  esac; }
# outputs.conf = where logs go. inputs.conf = what is collected.
conf_files(){ local d; for d in $UF $EN; do
  [ -n "$d" ] || continue
  find "$d/etc/system/local" "$d/etc/apps" -name "$1" -type f 2>/dev/null; done; }
targets(){ conf_files outputs.conf | xargs -r grep -hE '^[[:space:]]*server[[:space:]]*=' 2>/dev/null \
           | sed 's/.*=//' | tr ',' '\n' | tr -d ' ' | grep -v '^$' | sort -u; }

case "${1:-check}" in
# ============================================================ CHECK
check)
  echo "Splunk role on this box: $ROLE    expected indexer: $INDEXER:$RPORT"
  [ "$ROLE" = none ] && {
    sec "NO SPLUNK FOUND ON THIS BOX"
    echo "  Nothing under /opt/splunkforwarder or /opt/splunk."
    echo "  If this box is supposed to forward logs, that is a problem: either it was"
    echo "  never installed, or red team removed it. Check with your Splunk owner."
    echo "  Syslog fallback -- is anything being shipped the old way?"
    grep -rhsE '^[^#]*@@?[0-9]' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | sed 's/^/    /' || echo "    (no remote syslog configured either)"
    exit 0; }

  sec "SERVICE"
  if K=$(svc_kind); then
    case "$K" in
      systemd:*) printf '  managed by: systemd unit %s  ' "${K#systemd:}";;
      initd:*)   printf '  managed by: init.d script /etc/init.d/%s  ' "${K#initd:}";;
      cli:*)     printf '  managed by: NOTHING -- only the Splunk CLI (%s)  ' "${K#cli:}";;
    esac
    if svc_active "$K"; then echo "RUNNING"; else echo "NOT RUNNING  <-- your logs are not moving"; fi
    case "$K" in
      systemd:*) systemctl is-enabled "${K#systemd:}" 2>/dev/null | sed 's/^/  on boot: /';;
      cli:*)
        echo "  !! NO BOOT-START CONFIGURED. Splunk is running now, but nothing will"
        echo "     restart it. Red team CAN reboot your boxes, and after a reboot this"
        echo "     stays down: Splunk Query and Splunk Management both fail, and every"
        echo "     forwarder on the network has nowhere to send logs."
        echo "     The watchdog also cannot restart it (services.sh uses systemctl)."
        echo "     FIX IT:  sudo bash $0 fix     (offers to enable boot-start)";;
    esac
  else
    echo "  !! Splunk is installed but nothing manages it -- no systemd unit, no init"
    echo "     script, no usable binary. It will NOT come back after a reboot."
  fi
  # match the real binary, not any command line that merely mentions splunk
  if pgrep -x splunkd >/dev/null 2>&1; then
    pgrep -x splunkd | head -3 | while read -r p; do
      echo "  proc: pid $p $(readlink -f /proc/$p/exe 2>/dev/null)"; done
  else echo "  no splunkd process running"; fi

  if [ -n "$UF" ] || [ "$ROLE" = both ]; then
    sec "WHERE THIS BOX SENDS ITS LOGS (outputs.conf)"
    T=$(targets)
    if [ -z "$T" ]; then
      echo "  !! NO FORWARD TARGET CONFIGURED. This box is not sending anything."
      echo "     Fix with:  sudo bash $0 fix"
    else
      echo "$T" | while read -r t; do
        host=${t%%:*}
        if [ "$host" = "$INDEXER" ]; then echo "  ok  $t"
        else echo "  !! $t  <-- NOT your indexer ($INDEXER)."
             echo "         Red team re-pointing outputs.conf steals your logs AND blinds you."
             echo "         Confirm this is yours before you dismiss it."; fi
      done
    fi
    conf_files outputs.conf | sed 's/^/  config: /'

    sec "IS THE CONNECTION ACTUALLY UP?"
    if ss -tn 2>/dev/null | grep -q ":$RPORT .*ESTAB"; then
      ss -tnp 2>/dev/null | grep ":$RPORT " | grep ESTAB | sed 's/^/  /'
      echo "  ok -- an established connection to a $RPORT receiver exists"
    else
      echo "  !! no ESTABLISHED connection to port $RPORT."
      echo "     Either the indexer is down, the forwarder is dead, or something is blocking it."
      if have timeout; then
        timeout 4 bash -c "exec 9<>/dev/tcp/$INDEXER/$RPORT" 2>/dev/null \
          && echo "     (but $INDEXER:$RPORT IS reachable from here -- so it is the forwarder)" \
          || echo "     ($INDEXER:$RPORT is NOT reachable -- firewall, or the indexer is down)"
      fi
    fi

    sec "WHAT IS BEING COLLECTED (inputs.conf monitors)"
    conf_files inputs.conf | xargs -r grep -hE '^\[monitor|^\[script' 2>/dev/null | sort -u | sed 's/^/  /' \
      || echo "  !! no monitors configured -- the forwarder is running but collecting nothing"
  fi

  if [ -n "$EN" ]; then
    sec "THIS BOX IS AN INDEXER -- is it accepting data?"
    if ss -tln 2>/dev/null | grep -q ":$RPORT"; then echo "  ok  listening on $RPORT"
    else echo "  !! NOT listening on $RPORT -- no forwarder can send to it."
         echo "     Enable:  $EN/bin/splunk enable listen $RPORT -auth <user>:<pass>"; fi
    for p in 8000 8089; do
      ss -tln 2>/dev/null | grep -q ":$p" && echo "  ok  listening on $p" \
        || echo "  !! NOT listening on $p (8000 = web/query check, 8089 = SCORED mgmt check)"
    done
  fi

  sec "RECENT SPLUNK ERRORS"
  for l in "$HOME_DIR/var/log/splunk/splunkd.log"; do
    [ -r "$l" ] && grep -iE 'error|warn|refused|failed' "$l" 2>/dev/null | tail -8 | sed 's/^/  /'
  done
  echo
  echo "Nothing above was changed. To repair forwarding:  sudo bash $0 fix"
  ;;

# ============================================================ INDEXER
indexer)
  [ -n "$EN" ] || { echo "No Splunk Enterprise here ($ROLE). Run this ON the Splunk box (172.20.240.20)."; exit 1; }
  sec "LISTENERS"
  L=$(ss -tlnp 2>/dev/null | grep -E ":(8000|8089|$RPORT|514) ")
  [ -n "$L" ] && echo "$L" | sed 's/^/  /' || echo "  !! NONE of 8000/8089/$RPORT are listening -- Splunk is not serving anything"
  echo "  8000 = query check   8089 = SCORED management check   $RPORT = forwarders in"
  sec "FORWARDERS CURRENTLY CONNECTED (who is actually sending)"
  CONN=$(ss -tn 2>/dev/null | grep ":$RPORT " | grep ESTAB | awk '{print $NF}' | cut -d: -f1 | sort | uniq -c)
  if [ -n "$CONN" ]; then echo "$CONN" | sed 's/^/  /'
  else
    echo "  !! NOBODY is connected to $RPORT."
    echo "     No box is forwarding. Your logs are empty, the Splunk Query check may"
    echo "     fail, and you have no evidence for incident reports (20% of the score)."
    echo "     Go run 'sudo bash splunk.sh check' on Rocky Ecom and Ubuntu Email."
  fi
  echo
  echo "  Expect one line per forwarding box. Missing boxes are not sending -- go run"
  echo "  'sudo bash splunk.sh check' on each one."
  sec "ASK SPLUNK WHICH HOSTS HAVE REPORTED (needs a login)"
  cat <<EOT
  In the web UI (port 8000) or via CLI, run:
      | metadata type=hosts | eval last=strftime(lastTime,"%H:%M:%S") | table host last totalCount
  Any box missing from that list is not reaching the indexer.
  CLI equivalent:
      $EN/bin/splunk search '| metadata type=hosts' -auth <user>:<pass>
EOT
  sec "RECEIVING CONFIG"
  find "$EN/etc" -name inputs.conf 2>/dev/null | xargs -r grep -l splunktcp 2>/dev/null | sed 's/^/  /'
  find "$EN/etc" -name inputs.conf 2>/dev/null | xargs -r grep -hA2 'splunktcp' 2>/dev/null | head -10 | sed 's/^/  /'
  ;;

# ============================================================ FIX
fix)
  [ "$ROLE" = none ] && { echo "No Splunk installed here -- nothing to fix. Talk to your Splunk owner."; exit 1; }
  B=$HOME_DIR/bin/splunk
  K=$(svc_kind)
  echo "Splunk home: $HOME_DIR    indexer: $INDEXER:$RPORT    managed by: ${K:-nothing}"

  # No boot-start means a reboot takes Splunk down for good. Offer to register it.
  case "$K" in
    cli:*|"")
      echo
      echo "Splunk has no systemd unit and no init script, so it will NOT come back"
      echo "after a reboot -- and red team can reboot your boxes."
      # Splunk REFUSES to register boot-start while it is running, so this is
      # stop -> enable -> start. That is ~1-2 minutes of downtime: worth it, because
      # without boot-start a single reboot takes Splunk down permanently.
      RUNUSER=$(splunk_user)
      echo "  Splunk currently runs as: $RUNUSER  (the unit will be created for that user)"
      echo "  This needs Splunk STOPPED, so expect 1-2 minutes down. If scoring is live,"
      echo "  you will likely miss one check cycle -- far cheaper than losing it to a reboot."
      if ask "Stop Splunk, register boot-start as '$RUNUSER', then start it again?"; then
        echo "  stopping (as $RUNUSER -- Splunk refuses to be driven as root)..."
        as_splunk "$RUNUSER" "$B" stop 2>&1 | tail -3 | sed 's/^/    /'
        sleep 2
        if pgrep -x splunkd >/dev/null 2>&1; then
          echo "  !! Splunk did NOT stop -- it is still running. Not touching boot-start."
          echo "     Usually this means a permissions problem. Check:"
          echo "       ls -ld $HOME_DIR ; ps -o user= -p \$(pgrep -x splunkd | head -1)"
          echo "     Then stop it as root:  sudo $B stop"
          exit 1
        fi
        echo "  registering..."
        if "$B" enable boot-start -systemd-managed 1 -user "$RUNUSER" 2>&1 | sed 's/^/    /'; then
          systemctl daemon-reload 2>/dev/null
          K=$(svc_kind)
          case "$K" in
            systemd:*) U="${K#systemd:}"
              echo "  created unit: $U"
              systemctl enable "$U" 2>/dev/null
              echo "  starting (slow, give it a minute)..."
              systemctl start "$U" 2>&1 | sed 's/^/    /'
              sleep 10
              if svc_active "$K"; then
                echo "  RUNNING under systemd now"
                # Switching to systemd can leave Splunk's web tier (port 8000) down even
                # though splunkd itself is up. 8000 is the SCORED Splunk Query check, so
                # verify every port before calling this a success.
                echo "  verifying the scored ports came back (waiting up to 90s)..."
                miss=""
                for i in 1 2 3 4 5 6 7 8 9; do
                  miss=""
                  for p in 8000 8089 "$RPORT"; do
                    ss -tln 2>/dev/null | grep -q ":$p " || miss="$miss $p"; done
                  [ -z "$miss" ] && break
                  sleep 10
                done
                if [ -z "$miss" ]; then
                  echo "  all of 8000 / 8089 / $RPORT are listening -- good"
                else
                  echo "  !! STILL NOT LISTENING:$miss"
                  echo "     Port 8000 is the SCORED Splunk Query check. Do not leave it like this."
                  echo "     1. Try a restart first (helper services often start out of order):"
                  echo "          sudo systemctl restart ${K#systemd:}"
                  echo "     2. Check the web tier specifically:"
                  echo "          sudo tail -30 $HOME_DIR/var/log/splunk/web_service.log"
                  echo "     3. If 8000 will not come back, REVERT -- a scored service beats"
                  echo "        reboot survival:"
                  echo "          sudo systemctl stop ${K#systemd:} && sudo systemctl disable ${K#systemd:}"
                  echo "          sudo $B disable boot-start"
                  echo "          sudo -u $RUNUSER $B start"
                fi
              else
                echo "  !! did not come back. Start it the old way NOW so you are not down:"
                echo "       sudo -u $RUNUSER $B start"
                echo "     then check: tail -40 $HOME_DIR/var/log/splunk/splunkd.log"
              fi
              echo "  Add it to the watchdog:  sudo bash $0 watch";;
            *) echo "  !! no unit appeared. Starting Splunk again so you are not left down:"
               as_splunk "$RUNUSER" "$B" start 2>&1 | tail -3 | sed 's/^/    /';;
          esac
        else
          echo "  enable failed -- starting Splunk again so you are not left down:"
          as_splunk "$RUNUSER" "$B" start 2>&1 | tail -3 | sed 's/^/    /'
        fi
      fi;;
  esac

  if [ -n "$K" ] && ! svc_active "$K"; then
    echo; echo "Splunk is NOT running."
    ask "Start it?" && { case "$K" in cli:*) as_splunk "$(splunk_user)" "$B" start;; *) svc_do "$K" start;; esac; sleep 4; svc_active "$K" \
      && echo "  started" || { echo "  would not start. Logs:"; tail -15 "$HOME_DIR/var/log/splunk/splunkd.log" 2>/dev/null | sed 's/^/    /'; }; }
  fi

  if [ -n "$UF" ] || [ "$ROLE" = both ]; then
    T=$(targets)
    BAD=$(echo "$T" | grep -v "^$INDEXER:" | grep -v '^$')
    if [ -n "$BAD" ]; then
      echo; echo "This box forwards to something that is NOT your indexer:"
      echo "$BAD" | sed 's/^/    /'
      echo "  That is either a config you did not know about, or red team stealing your logs."
      if ask "Remove those targets and point at $INDEXER:$RPORT?"; then
        echo "$BAD" | while read -r b; do [ -n "$b" ] && "$B" remove forward-server "$b" 2>/dev/null; done
        "$B" add forward-server "$INDEXER:$RPORT" 2>/dev/null \
          || echo "  CLI needs auth: $B add forward-server $INDEXER:$RPORT -auth ${SPLUNK_USER:-admin}:<pass>"
      fi
    fi
    if [ -z "$T" ]; then
      echo; echo "No forward target configured at all."
      if ask "Point this box at $INDEXER:$RPORT?"; then
        "$B" add forward-server "$INDEXER:$RPORT" 2>/dev/null \
          || echo "  CLI needs auth: $B add forward-server $INDEXER:$RPORT -auth ${SPLUNK_USER:-admin}:<pass>"
      fi
    fi
    MON=$(conf_files inputs.conf | xargs -r grep -hE '^\[monitor' 2>/dev/null | head -1)
    if [ -z "$MON" ]; then
      echo; echo "No file monitors configured -- the forwarder would send nothing."
      if ask "Monitor /var/log on this box?"; then
        "$B" add monitor /var/log 2>/dev/null \
          || echo "  CLI needs auth: $B add monitor /var/log -auth ${SPLUNK_USER:-admin}:<pass>"
      fi
    fi
  fi

  if [ -n "$EN" ]; then
    if ! ss -tln 2>/dev/null | grep -q ":$RPORT"; then
      echo; echo "This indexer is NOT listening on $RPORT, so nothing can forward to it."
      ask "Enable receiving on $RPORT?" && { "$B" enable listen "$RPORT" 2>/dev/null \
        || echo "  CLI needs auth: $B enable listen $RPORT -auth ${SPLUNK_USER:-admin}:<pass>"; }
    fi
  fi

  echo
  if [ -n "$K" ] && ask "Restart Splunk now to apply? (takes a minute or two)"; then
    svc_do "$K" restart; sleep 8
    svc_active "$K" && echo "  running" || echo "  FAILED to come back -- check splunkd.log"
  fi
  echo "Re-check with:  sudo bash $0 check"
  ;;

# ============================================================ WATCH
watch)
  [ "$ROLE" = none ] && { echo "No Splunk here; nothing to add."; exit 1; }
  CFG=${CFG:-/etc/ccdc/services.conf}
  mkdir -p "$(dirname "$CFG")"
  K=$(svc_kind)
  case "$K" in
    systemd:*) U="${K#systemd:}"; echo "  Splunk unit: $U (the watchdog can restart it)";;
    initd:*|cli:*)
      U="FIXME-splunk"
      echo "  !! Splunk is managed by ${K%%:*}, not a systemd unit. The watchdog can ALERT"
      echo "     but cannot restart it (services.sh uses systemctl). Restart by hand:"
      echo "       $( [ "${K%%:*}" = initd ] && echo "/etc/init.d/${K#initd:} restart" || echo "${K#cli:} restart" )";;
    *)
      U="FIXME-splunk"
      echo "  !! Nothing manages Splunk on this box. Adding ALERT-ONLY checks: the watchdog"
      echo "     will tell you when Splunk is down but cannot restart it. Look for a unit:"
      echo "       systemctl list-units --all | grep -i splunk"
      echo "     then put its real name in $CFG.";;
  esac
  add(){ grep -qF "$1" "$CFG" 2>/dev/null || { echo "$1" >> "$CFG"; echo "  added: $1"; }; }
  if [ -n "$EN" ]; then
    add "tcp $RPORT $U"      # forwarders in -- if this dies every box stops logging
    add "tcp 8000 $U"        # Splunk Query scored check
    add "tcp 8089 $U"        # Splunk Management SCORED check
  fi
  [ -n "$UF" ] && [ -z "$EN" ] && add "unit - $U"
  echo "Watch list: $CFG"
  echo "Start the watchdog if it is not already running:  sudo bash services.sh watch 30 &"
  ;;
*) awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1{exit}' "$0";;
esac
exit 0
