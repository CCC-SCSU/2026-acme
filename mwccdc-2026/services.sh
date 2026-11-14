#!/usr/bin/env bash
# services.sh -- keep scored services alive.
#   services.sh discover            map listening ports -> systemd units, write a watch list you can edit
#   services.sh check               one-shot health check of everything in the watch list
#   services.sh watch [sec=30]      loop: check, RESTART anything that is down, log it
#   services.sh monitor [sec=30]    same loop but never restarts (alert only)
#   services.sh status              show the log tail and restart counts
#   services.sh add tcp 80 apache2  add a check by hand   (also: add http http://localhost/ apache2)
# Watch list: /etc/ccdc/services.conf   lines are:  TYPE TARGET UNIT
#   tcp  <port>            <unit>    port must be listening
#   udp  <port>            <unit>    port must be bound
#   http <url>             <unit>    URL must return a non-5xx status
#   unit <name>            <unit>    systemd unit must be active (TARGET ignored)
# Restarts are rate-limited to MAX_RESTARTS (default 3) per unit per WINDOW (default 900s): a service
# that keeps dying needs a human, and a restart loop can look worse to the scoring engine than a clean stop.
export PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
CFG=${CFG:-/etc/ccdc/services.conf}
LOG=/root/ccdc-logs/services.log
STATE=/run/ccdc-svc
MAX_RESTARTS=${MAX_RESTARTS:-3}
WINDOW=${WINDOW:-900}
mkdir -p "$(dirname "$CFG")" /root/ccdc-logs "$STATE" 2>/dev/null
log(){ echo "$(date '+%F %T') $*" >> "$LOG"; }
have(){ command -v "$1" >/dev/null 2>&1; }

unit_for_pid(){ # systemd unit owning a pid, via its cgroup
  local p=$1 u
  [ -r "/proc/$p/cgroup" ] || return 1
  u=$(grep -oE '[^/]+\.service' "/proc/$p/cgroup" 2>/dev/null | head -1)
  [ -n "$u" ] && echo "$u"
}
bound_ports(){ # $1=tcp|udp -> list of bound ports (robust across ss versions/flags)
  local f=t; [ "$1" = udp ] && f=u
  ss -${f}ln 2>/dev/null | awk 'NR>1{for(i=1;i<=NF;i++) if($i ~ /:[0-9]+$/){print $i; break}}' | sed 's/.*://'
}
can_connect(){ # real TCP connect, which is what the scoring engine actually does
  timeout 3 bash -c "exec 9<>/dev/tcp/$1/$2" 2>/dev/null
}
host_ip(){ ip -4 route get 1.1.1.1 2>/dev/null | grep -oE 'src [0-9.]+' | awk '{print $2}' | head -1; }
port_listening(){ # $1=tcp|udp $2=port
  if [ "$1" = tcp ]; then
    can_connect 127.0.0.1 "$2" && return 0
    local h; h=$(host_ip); [ -n "$h" ] && can_connect "$h" "$2" && return 0
  fi
  bound_ports "$1" | grep -qx "$2"      # fallback / UDP: is it bound at all
}
http_ok(){ # non-5xx and not a connection failure
  local code
  if have curl; then
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -k "$1" 2>/dev/null)
  elif have wget; then
    wget -q -T 8 --no-check-certificate -O /dev/null "$1" 2>/dev/null && code=200 || code=000
  else return 0; fi   # no http client: do not claim failure
  [ -n "$code" ] && [ "$code" != 000 ] && [ "${code:0:1}" != 5 ]
}
unit_active(){ systemctl is-active --quiet "$1" 2>/dev/null; }

check_one(){ # TYPE TARGET UNIT -> 0 ok, 1 down ; prints a status line
  local t=$1 tgt=$2 unit=$3 ok=1 detail=""
  case "$t" in
    tcp|udp) port_listening "$t" "$tgt" && ok=0; detail="$t/$tgt";;
    http)    http_ok "$tgt" && ok=0;              detail="$tgt";;
    unit)    unit_active "$unit" && ok=0;         detail="unit";;
    *) echo "  ?? unknown check type '$t'"; return 0;;
  esac
  if [ "$ok" = 0 ]; then printf '  OK   %-22s %s\n' "$unit" "$detail"
  else printf '  DOWN %-22s %s%s\n' "$unit" "$detail" "$(unit_active "$unit" || echo '  (unit not active)')"; fi
  return $ok
}

restart_allowed(){ # rate limit per unit
  local u=$1                      # NOTE: keep these on separate lines --
  local f="$STATE/${u//\//_}.restarts"   # in `local a=$1 b=$a`, b is expanded before a is set
  local now; now=$(date +%s)
  local n=0 line keep=""
  [ -f "$f" ] && while read -r line; do
    [ -n "$line" ] && [ $((now - line)) -lt "$WINDOW" ] && { keep="$keep$line"$'\n'; n=$((n+1)); }
  done < "$f"
  printf '%s' "$keep" > "$f"
  [ "$n" -lt "$MAX_RESTARTS" ]
}
record_restart(){ date +%s >> "$STATE/${1//\//_}.restarts"; }

load_cfg(){ [ -f "$CFG" ] || { echo "no watch list at $CFG -- run: $0 discover"; exit 1; }; }

case "$1" in
discover)
  echo "# ccdc watch list -- generated $(date)" > "$CFG.new"
  echo "# TYPE TARGET UNIT   (edit freely; delete anything that is not a scored service)" >> "$CFG.new"
  have ss || { echo "'ss' not found (install iproute2 / iproute)"; exit 1; }
  found=0
  for proto in t u; do
    ss -${proto}lnp 2>/dev/null | tail -n +2 | while read -r line; do
      addr=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i ~ /:[0-9]+$/){print $i; exit}}')
      [ -n "$addr" ] || continue
      case "$addr" in 127.*|\[::1\]*|*%lo:*) continue;; esac
      port=${addr##*:}; [[ $port =~ ^[0-9]+$ ]] || continue
      pid=$(echo "$line" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
      unit=""; [ -n "$pid" ] && unit=$(unit_for_pid "$pid")
      if [ -z "$unit" ]; then
        pname=$(echo "$line" | grep -oE 'users:\(\("[^"]+' | head -1 | sed 's/.*"//')
        # a process name is not a unit name: only accept it if a matching unit really exists
        if [ -n "$pname" ] && systemctl cat "$pname.service" >/dev/null 2>&1; then unit="$pname.service"
        elif [ -n "$pname" ]; then unit="FIXME-$pname"
        else unit="FIXME-port$port"; fi
      fi
      [ "$proto" = t ] && echo "tcp $port $unit" || echo "udp $port $unit"
    done >> "$CFG.new"
  done
  # HTTP checks for anything on a web port
  for p in 80 443 8000 8080 8443; do
    grep -q "^tcp $p " "$CFG.new" 2>/dev/null || continue
    u=$(awk -v p="$p" '$1=="tcp" && $2==p {print $3}' "$CFG.new" | head -1)
    case "$p" in 443|8443) s=https;; *) s=http;; esac
    echo "http $s://127.0.0.1:$p/ $u" >> "$CFG.new"
  done
  sort -u -k1,2 "$CFG.new" -o "$CFG.new"
  if [ -f "$CFG" ]; then echo "existing $CFG kept; new findings in $CFG.new -- diff them:"; diff "$CFG" "$CFG.new"
  else mv "$CFG.new" "$CFG"; fi
  echo; echo "--- $CFG ---"; cat "$CFG" 2>/dev/null || cat "$CFG.new"
  echo; echo "EDIT THIS FILE: remove ports that are not scored services. Any FIXME-* line needs a real"
  echo "systemd unit name before it can be auto-restarted (find it with: systemctl list-units --type=service)."
  echo "Then: $0 check"
  ;;
add)
  shift; [ $# -eq 3 ] || { echo "usage: $0 add <tcp|udp|http|unit> <target> <unit>"; exit 1; }
  mkdir -p "$(dirname "$CFG")"; echo "$1 $2 $3" >> "$CFG"; echo "added: $1 $2 $3"
  ;;
check)
  load_cfg; down=0
  echo "Checking $(grep -cvE '^\s*(#|$)' "$CFG") service checks from $CFG"
  while read -r t tgt unit; do
    case "$t" in ''|\#*) continue;; esac
    check_one "$t" "$tgt" "$unit" || down=$((down+1))
  done < "$CFG"
  echo; [ "$down" = 0 ] && echo "all checks passing" || echo "$down check(s) DOWN"
  exit 0
  ;;
watch|monitor)
  load_cfg
  RESTART=1; [ "$1" = monitor ] && RESTART=0
  iv=${2:-30}
  echo "$([ $RESTART = 1 ] && echo 'watching + restarting' || echo 'monitoring only') every ${iv}s. Log: $LOG"
  echo "Stop with: pkill -f 'services.sh $1'"
  log "=== $1 started (interval ${iv}s, restart=$RESTART) ==="
  while true; do
    while read -r t tgt unit; do
      case "$t" in ''|\#*) continue;; esac
      if ! check_one "$t" "$tgt" "$unit" >/dev/null 2>&1; then
        log "DOWN $unit ($t $tgt)"
        if [ "$RESTART" = 1 ] && [ -n "$unit" ] && [ "${unit#FIXME-}" = "$unit" ]; then
          if restart_allowed "$unit"; then
            log "restarting $unit"
            if systemctl restart "$unit" >>"$LOG" 2>&1; then
              record_restart "$unit"; sleep 3
              if check_one "$t" "$tgt" "$unit" >/dev/null 2>&1; then log "RECOVERED $unit"
              else log "still down after restart: $unit"; fi
            else log "restart FAILED for $unit -- needs a human"; fi
          else
            log "rate limit hit for $unit ($MAX_RESTARTS restarts in ${WINDOW}s) -- NOT restarting, needs a human"
          fi
        fi
      fi
    done < "$CFG"
    sleep "$iv"
  done
  ;;
status)
  echo "watch list: $CFG"; echo "log: $LOG"; echo
  echo "--- restart counts (last ${WINDOW}s) ---"
  for f in "$STATE"/*.restarts; do [ -f "$f" ] || continue
    echo "$(basename "$f" .restarts): $(wc -l < "$f")"; done
  echo; echo "--- last 25 log lines ---"; tail -25 "$LOG" 2>/dev/null || echo "(no log yet)"
  ;;
*) awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1{exit}' "$0";;
esac
