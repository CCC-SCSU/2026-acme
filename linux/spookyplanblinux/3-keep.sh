#!/bin/sh
# 3-keep.sh -- keeps your scored services alive. Checks ports, restarts what died.
#   sudo sh 3-keep.sh 80 443 3306          watch these ports (it works out the service name itself)
#   sudo sh 3-keep.sh 80=nginx 3306=mysql  tell it the service name yourself
#   sudo sh 3-keep.sh check 80 443         check once and exit, restart nothing
# Run it in the background so it keeps going:   sudo sh 3-keep.sh 80 443 >/dev/null 2>&1 &
# Stop it with:                                 sudo pkill -f 3-keep.sh
# Log: /root/keep.log       Restarts are capped at 3 per port per 15 minutes.
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
LOG=/root/keep.log
IV=${IV:-30}
MAXR=${MAXR:-3}
WIN=${WIN:-900}
log(){ echo "$(date '+%F %T') $*" | tee -a "$LOG"; }

# --- is this TCP port listening? works with ss, netstat, or neither ---
listening(){
  P=$1
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | awk -v p=":$P\$" 'NR>1{for(i=1;i<=NF;i++) if($i ~ p){f=1}} END{exit !f}' && return 0
    return 1
  fi
  if command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk -v p=":$P\$" '{for(i=1;i<=NF;i++) if($i ~ p){f=1}} END{exit !f}' && return 0
    return 1
  fi
  for f in /proc/net/tcp /proc/net/tcp6; do
    [ -r "$f" ] || continue
    awk -v want="$P" 'function h2d(s, i,c,n,d){n=0;s=toupper(s);for(i=1;i<=length(s);i++){c=substr(s,i,1);d=index("0123456789ABCDEF",c)-1;n=n*16+d}return n}
      NR>1 && $4=="0A" {split($2,a,":"); if (h2d(a[2])==want) f=1} END{exit !f}' "$f" && return 0
  done
  return 1
}

# --- which systemd unit owns the process on this port? ---
unit_on_port(){
  command -v ss >/dev/null 2>&1 || return 1
  PID=$(ss -ltnp 2>/dev/null | grep ":$1 " | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
  [ -n "$PID" ] || return 1
  [ -r "/proc/$PID/cgroup" ] || return 1
  grep -o '[^/]*\.service' "/proc/$PID/cgroup" 2>/dev/null | head -1
}

if [ "$1" = check ]; then
  shift
  [ -n "$1" ] || { echo "usage: sudo sh $0 check 80 443"; exit 1; }
  BAD=0
  for a in "$@"; do
    P=$(echo "$a" | cut -d= -f1)
    if listening "$P"; then echo "  OK   port $P"
    else echo "  DOWN port $P"; BAD=$((BAD+1)); fi
  done
  [ "$BAD" = 0 ] && echo "all up" || echo "$BAD port(s) down"
  exit 0
fi

[ -n "$1" ] || { echo "Usage: sudo sh $0 80 443 3306      (or 80=nginx)"; exit 1; }
command -v systemctl >/dev/null 2>&1 || log "NOTE: no systemctl here; this will alert but cannot restart anything."

# --- work out the service name for each port while things are still up ---
PAIRS=""
for a in "$@"; do
  P=$(echo "$a" | cut -d= -f1); U=$(echo "$a" | cut -s -d= -f2)
  case "$P" in *[!0-9]*|'') echo "bad port '$a'"; exit 1;; esac
  [ "$P" -ge 1 ] && [ "$P" -le 65535 ] || { echo "port out of range: $a"; exit 1; }
  if [ -z "$U" ]; then
    U=$(unit_on_port "$P")
    if [ -n "$U" ]; then echo "port $P -> $U"
    else echo "port $P -> UNKNOWN (will alert but not restart; rerun as  $0 $P=theunitname)"; U="-"; fi
  else
    echo "port $P -> $U (you told me)"
  fi
  PAIRS="$PAIRS $P=$U"
done
echo
log "=== keep started: ports$(echo "$PAIRS" | sed 's/=[^ ]*//g'), every ${IV}s, max $MAXR restarts per ${WIN}s ==="
echo "running. Log: $LOG   Stop with: sudo pkill -f 3-keep.sh"

while true; do
  for pair in $PAIRS; do
    P=${pair%%=*}; U=${pair#*=}
    if listening "$P"; then continue; fi
    log "DOWN port $P (${U})"
    [ "$U" = "-" ] && continue
    command -v systemctl >/dev/null 2>&1 || continue
    CF=/tmp/.keep-$P.count
    NOW=$(date +%s); N=0; KEEP=""
    if [ -f "$CF" ]; then
      while read -r t; do
        [ -n "$t" ] || continue
        if [ $((NOW - t)) -lt "$WIN" ]; then KEEP="$KEEP$t
"; N=$((N+1)); fi
      done < "$CF"
    fi
    printf '%s' "$KEEP" > "$CF"
    if [ "$N" -ge "$MAXR" ]; then
      log "port $P restarted $N times in ${WIN}s already -- NOT restarting again. A human needs to look."
      continue
    fi
    log "restarting $U"
    if systemctl restart "$U" >> "$LOG" 2>&1; then
      echo "$NOW" >> "$CF"
      sleep 5
      if listening "$P"; then log "RECOVERED port $P"; else log "port $P still down after restarting $U"; fi
    else
      log "restart of $U FAILED -- fix it by hand"
    fi
  done
  sleep "$IV"
done
