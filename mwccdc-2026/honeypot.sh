#!/usr/bin/env bash
# honeypot.sh -- tripwire. Alerts when someone runs a recon/attack command, and lets YOU
# decide whether to kill their session. It never kills anything on its own by default.
#
#   sudo bash honeypot.sh arm              install tripwires (default command list)
#   sudo bash honeypot.sh arm whoami nc    ...or name your own commands
#   sudo bash honeypot.sh watch            LIVE alerts + the kill command for each. Run in a pane.
#   sudo bash honeypot.sh alerts [n]       show the last n alerts (default 30)
#   sudo bash honeypot.sh kill pts/3       kill every process on that terminal
#   sudo bash honeypot.sh kill 12345       kill that PID's whole session
#   sudo bash honeypot.sh status           what is armed, and is PATH ordered correctly
#   sudo bash honeypot.sh bait             plant decoy credential files that alert when read
#   sudo bash honeypot.sh disarm           remove every tripwire (restores normal commands)
#
# HOW IT WORKS: a tiny wrapper is placed in /usr/local/bin, which Debian/Ubuntu/Rocky put
# BEFORE /usr/bin in PATH. The wrapper logs the attempt and then runs the real command, so
# nothing breaks -- a legitimate user notices nothing.
#
# HONEST LIMITS
#  * It is a TRIPWIRE, not a wall. Anyone invoking /usr/bin/whoami by absolute path, or
#    using a shell with its own PATH, is not caught. Use 'arm-audit' for that (needs auditd).
#  * 'id' and 'hostname' are deliberately NOT in the default list: this kit's own scripts
#    call them constantly and you would drown in your own noise.
#  * The scoring engine may run a command over SSH as part of its check. That is why
#    nothing is killed automatically. YOU decide, after reading the alert.
export PATH="/usr/sbin:/sbin:/usr/bin:/bin:$PATH"
case "$1" in -h|--help|help|"")
  awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0;; esac
[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo bash $0 $*"; exit 1; }

WRAPDIR=/usr/local/bin
LOG=/var/log/ccdc-honey.log
STATE=/etc/ccdc/honey.armed
BAITLOG=/var/log/ccdc-bait.log
# recon + reverse-shell + persistence tooling. No 'id'/'hostname' (kit noise), no 'passwd'
# family (this kit invokes them). Add those yourself if you want them.
DEFAULT_CMDS="whoami nc ncat netcat socat nmap masscan chattr tcpdump"
mkdir -p /etc/ccdc 2>/dev/null
touch "$LOG" 2>/dev/null; chmod 600 "$LOG" 2>/dev/null

ask(){ local a; read -r -p "$1 [y/N] " a || return 1; [ "$a" = y ] || [ "$a" = Y ]; }

real_path(){ # the genuine binary, skipping our own wrapper dir
  local c=$1 p
  for p in /usr/bin /bin /usr/sbin /sbin; do
    [ -x "$p/$c" ] && { echo "$p/$c"; return 0; }; done
  return 1
}

make_wrapper(){ # $1=command name  $2=real path
  cat > "$WRAPDIR/$1" <<EOF
#!/bin/sh
# ccdc tripwire for '$1'. Logs, then runs the real command. Never blocks it.
# PATH is pinned below so this wrapper can never invoke itself.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
{
  # 'tty' prints "not a tty" on stdout AND exits non-zero, so only trust /dev/* output
  TTY=\$(/usr/bin/tty 2>/dev/null)
  case "\$TTY" in /dev/*) ;; *) TTY=no-tty;; esac
  WHO=\$(/usr/bin/id -un 2>/dev/null || echo "?")
  # strip newlines and the field delimiter so one record stays one line
  PCMD=\$(/bin/cat /proc/\$PPID/cmdline 2>/dev/null | /usr/bin/tr '\\0|\\n' '  ' | /usr/bin/head -c 100)
  ARGS=\$(/usr/bin/printf '%s' "\$*" | /usr/bin/tr '|\\n' '  ' | /usr/bin/head -c 60)
  /usr/bin/printf '%s|%s|%s|%s|%s|%s|%s\\n' \\
    "\$(/bin/date '+%F %T')" "$1" "\$WHO" "\$TTY" "\$PPID" "\$PCMD" "\$ARGS" >> $LOG
} 2>/dev/null
exec $2 "\$@"
EOF
  chmod 755 "$WRAPDIR/$1"
}

case "$1" in
# ---------------------------------------------------------------- ARM
arm)
  shift
  CMDS=${*:-$DEFAULT_CMDS}
  case ":$PATH:" in *":$WRAPDIR:"*) ;; *) echo "NOTE: $WRAPDIR is not in root's PATH right now; wrappers still work for normal logins.";; esac
  touch "$STATE"      # APPEND -- do not truncate, or a second 'arm' forgets the first
  armed=0; skipped=""
  for c in $CMDS; do
    if [ -f "$WRAPDIR/$c" ] && ! head -2 "$WRAPDIR/$c" 2>/dev/null | grep -q 'ccdc tripwire'; then
      skipped="$skipped $c(existing file)"; continue; fi
    R=$(real_path "$c") || { skipped="$skipped $c(not installed)"; continue; }
    make_wrapper "$c" "$R"
    grep -qx "$c $R" "$STATE" 2>/dev/null || echo "$c $R" >> "$STATE"
    armed=$((armed+1))
    printf '  armed %-10s -> real at %s\n' "$c" "$R"
  done
  [ -n "$skipped" ] && echo "  skipped:$skipped"
  echo
  echo "$armed tripwire(s) armed. Alerts -> $LOG"
  echo "Watch them live in another pane:   sudo bash $0 watch"
  echo
  echo "Sanity check -- this should look completely normal:"
  echo "    whoami"
  echo "and then an alert should appear in the log."
  ;;

# ---------------------------------------------------------------- STATUS
status)
  echo "PATH order check (wrapper dir must come BEFORE /usr/bin):"
  echo "  PATH=$PATH"
  case "$PATH" in
    *"$WRAPDIR"*) 
      pre=$(echo "$PATH" | tr ':' '\n' | grep -n -x -e "$WRAPDIR" -e /usr/bin | head -2 | cut -d: -f1 | tr '\n' ' ')
      set -- $pre
      [ "${1:-9}" -lt "${2:-0}" ] 2>/dev/null && echo "  OK -- $WRAPDIR precedes /usr/bin" || echo "  !! /usr/bin comes first; wrappers will be bypassed in THIS shell";;
    *) echo "  !! $WRAPDIR not in PATH for this shell";;
  esac
  echo
  echo "Armed tripwires:"
  if [ -s "$STATE" ]; then
    while read -r c r; do
      if [ -f "$WRAPDIR/$c" ] && head -2 "$WRAPDIR/$c" | grep -q 'ccdc tripwire'; then
        printf '  ok      %-10s (real: %s)\n' "$c" "$r"
      else printf '  MISSING %-10s <-- wrapper gone. Red team may have removed it.\n' "$c"; fi
    done < "$STATE"
  else echo "  none -- run: sudo bash $0 arm"; fi
  echo
  echo "Alerts logged: $(wc -l < "$LOG" 2>/dev/null || echo 0)   ($LOG)"
  [ -s "$BAITLOG" ] && echo "Bait hits: $(wc -l < "$BAITLOG")   ($BAITLOG)"
  ;;

# ---------------------------------------------------------------- ALERTS
alerts)
  n=${2:-30}
  [ -s "$LOG" ] || { echo "no alerts yet"; exit 0; }
  printf '%-19s %-9s %-9s %-10s %s\n' TIME CMD USER TTY "PARENT / ARGS"
  tail -n "$n" "$LOG" | while IFS='|' read -r t c w y p pc a; do
    printf '%-19s %-9s %-9s %-10s %s %s\n' "$t" "$c" "$w" "$y" "$pc" "$a"
  done
  ;;

# ---------------------------------------------------------------- WATCH
watch)
  MYTTY=$(tty 2>/dev/null); case "$MYTTY" in /dev/*) ;; *) MYTTY=no-tty;; esac
  echo "Watching $LOG for tripwire hits. Your terminal is $MYTTY (it will never be suggested as a kill target)."
  echo "Ctrl-C to stop. Nothing is killed automatically."
  echo
  [ -f "$LOG" ] || touch "$LOG"
  tail -n 0 -F "$LOG" 2>/dev/null | while IFS='|' read -r t c w y p pc a; do
    printf '\007'
    echo "=================================================================="
    echo " TRIPWIRE  $t"
    echo "   command : $c $a"
    echo "   user    : $w"
    echo "   terminal: $y"
    echo "   parent  : pid $p  $pc"
    if [ "$y" = "no-tty" ]; then
      echo "   -> NO TERMINAL. This is a script or service, not someone typing."
      echo "      Often legitimate. Check the parent above before reacting."
    elif [ "$y" = "$MYTTY" ]; then
      echo "   -> THIS IS YOUR OWN TERMINAL. Ignore it."
    else
      echo "   -> INTERACTIVE SESSION. Someone is typing on $y."
      echo "      Who is on it:  who | grep ${y#/dev/}"
      echo "      KILL IT:       sudo bash $0 kill ${y#/dev/}"
    fi
    echo "=================================================================="
  done
  ;;

# ---------------------------------------------------------------- KILL
kill)
  T=$2
  [ -n "$T" ] || { echo "usage: $0 kill <pts/3 | PID>"; exit 1; }
  MYTTY=$(tty 2>/dev/null); case "$MYTTY" in /dev/*) MYTTY=${MYTTY#/dev/};; *) MYTTY="";; esac
  if echo "$T" | grep -qE '^[0-9]+$'; then
    kill -0 "$T" 2>/dev/null || { echo "no such pid $T"; exit 1; }
    SID=$(ps -o sess= -p "$T" 2>/dev/null | tr -d ' ')
    PTTY=$(ps -o tty= -p "$T" 2>/dev/null | tr -d ' ')
    echo "pid $T  tty=$PTTY  session=$SID"
    ps -o pid,tty,user,args --sid "$SID" 2>/dev/null | head -12 | sed 's/^/  /'
    [ -n "$MYTTY" ] && [ "$PTTY" = "$MYTTY" ] && { echo "REFUSING: that is your own terminal."; exit 1; }
    ask "Kill every process in session $SID?" || { echo "nothing killed"; exit 0; }
    pkill -9 -s "$SID" 2>/dev/null; echo "killed session $SID"
  else
    T=${T#/dev/}
    [ -n "$MYTTY" ] && [ "$T" = "$MYTTY" ] && { echo "REFUSING: $T is your own terminal."; exit 1; }
    echo "Processes on $T:"
    ps -o pid,tty,user,etime,args -t "$T" 2>/dev/null | head -12 | sed 's/^/  /'
    who 2>/dev/null | grep -- "$T" | sed 's/^/  login: /'
    ps -o pid= -t "$T" >/dev/null 2>&1 || { echo "nothing running on $T"; exit 1; }
    echo
    echo "NOTE: if this is the scoring engine's SSH session, killing it fails that check."
    ask "Kill everything on $T?" || { echo "nothing killed"; exit 0; }
    pkill -9 -t "$T" 2>/dev/null
    echo "killed. Log the eviction for your incident report:"
    echo "  $(date '+%F %T') killed session on $T" >> /root/incidents.txt 2>/dev/null
    echo "  (appended to /root/incidents.txt)"
  fi
  ;;

# ---------------------------------------------------------------- BAIT
bait)
  echo "Planting decoy files. Reading one is a strong signal: nothing legitimate touches them."
  mkdir -p /root/.ssh-backup 2>/dev/null
  for f in /root/passwords.txt /root/.ssh-backup/id_rsa.bak /home/sysadmin/creds.txt; do
    d=$(dirname "$f"); [ -d "$d" ] || continue
    cat > "$f" <<'EOT'
# Infrastructure credentials -- DO NOT DISTRIBUTE
splunk_admin: Sp1unk-Adm1n-2026
mysql_root:   r00t-db-pass-2026
vyos:         Vy0S-r0uter-2026
EOT
    chmod 600 "$f"
    echo "  planted $f"
  done
  echo
  if command -v auditctl >/dev/null 2>&1; then
    for f in /root/passwords.txt /root/.ssh-backup/id_rsa.bak /home/sysadmin/creds.txt; do
      [ -f "$f" ] && auditctl -w "$f" -p r -k ccdc_bait 2>/dev/null && echo "  auditd watching $f"
    done
    echo "  Check hits with:  ausearch -k ccdc_bait -i"
  else
    echo "  auditd not installed, so no read-alerting. Falling back to access-time checks:"
    echo "    sudo bash $0 baitcheck      compares access times"
    for f in /root/passwords.txt /root/.ssh-backup/id_rsa.bak /home/sysadmin/creds.txt; do
      [ -f "$f" ] && stat -c '%X %n' "$f"; done > /etc/ccdc/bait.atime 2>/dev/null
  fi
  echo
  echo "These are FAKE credentials. They are not valid anywhere. If red team tries them,"
  echo "that attempt shows up in your logs and is excellent incident-report material."
  ;;

baitcheck)
  [ -s /etc/ccdc/bait.atime ] || { echo "no baseline -- run: sudo bash $0 bait"; exit 1; }
  hit=0
  while read -r old f; do
    [ -f "$f" ] || continue
    new=$(stat -c '%X' "$f" 2>/dev/null)
    if [ "$new" != "$old" ]; then
      echo "  !! READ: $f  (at $(date -d @"$new" '+%F %T' 2>/dev/null))"
      echo "     $(date '+%F %T') decoy file read: $f" >> /root/incidents.txt 2>/dev/null
      hit=1
    fi
  done < /etc/ccdc/bait.atime
  [ "$hit" = 0 ] && echo "  no decoy files have been read"
  ;;

# ---------------------------------------------------------------- DISARM
disarm)
  n=0
  # sweep EVERY file in the wrapper dir carrying our marker, so nothing is orphaned
  # even if the state file was lost or tampered with
  for f in "$WRAPDIR"/*; do
    [ -f "$f" ] || continue
    if head -2 "$f" 2>/dev/null | grep -q 'ccdc tripwire'; then
      rm -f "$f" && { echo "  removed tripwire: $(basename "$f")"; n=$((n+1)); }
    fi
  done
  rm -f "$STATE"
  [ "$n" = 0 ] && echo "nothing was armed"
  command -v auditctl >/dev/null 2>&1 && auditctl -D -k ccdc_bait 2>/dev/null
  echo "disarmed. Alert log kept at $LOG"
  ;;
*) awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1{exit}' "$0";;
esac
exit 0
