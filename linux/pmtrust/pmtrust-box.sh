#!/bin/bash
# pmtrust-box.sh -- staging-host helper: move the agent, snapshots and plans to/from the boxes.
#
# Purpose : wraps scp/ssh for the pmtrust workflow so nobody retypes paths under time pressure.
#           It never runs anything on a box except the bundled busybox agent (tweety: /bin/sh).
# Hosts   : team 37 (Acme LLC). Internal 192.168.220.Y; with VIA=ext uses 10.100.137.Y (1:1 NAT).
#           daffy .11  roadrunner .12  foghorn .13  porky .67  sylvester .69  elmer .77
#           taz .169  marvin .199  ysam .234  tweety .1
# Run     : ./pmtrust-box.sh collect <host> [--hash-list FILE]   push agent, snapshot, pull to snaps/
#           ./pmtrust-box.sh apply <host> <plandir> [--apply|--verify|--rollback WORKDIR]
#                                                               push plan (once) and run apply.sh
#           ./pmtrust-box.sh fetch-evidence <host>              pull /var/lib/pmtrust (logs, manifests)
#           env: SSH_USER (default root), VIA=ext, AGENT_DIR (default ./agent-build), SSH_OPTS
# Revert  : ./pmtrust-box.sh apply <host> <plandir> --rollback /var/lib/pmtrust/run-<time>
# Notes   : no passwords are stored; ssh prompts or uses your agent/keys. Credentials the scoring
#           engine checks must still be changed only through Quotient password change requests.
set -euo pipefail
TEAM=37
declare -A IP=([tweety]=1 [daffy]=11 [roadrunner]=12 [foghorn]=13 [porky]=67 [sylvester]=69
               [elmer]=77 [taz]=169 [marvin]=199 [ysam]=234)
SSH_USER=${SSH_USER:-root}
AGENT_DIR=${AGENT_DIR:-./agent-build}
SSH_OPTS=${SSH_OPTS:-"-o ConnectTimeout=10"}
LOG=./pmtrust-box.log
log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG" >&2; }

addr() {
    local y=${IP[$1]:-}
    [ -n "$y" ] || { echo "unknown host '$1' (known: ${!IP[*]})" >&2; exit 64; }
    if [ "${VIA:-int}" = ext ]; then echo "10.100.1$TEAM.$y"; else echo "192.168.220.$y"; fi
}
remote_dir() { [ "$SSH_USER" = root ] && echo /root/pmtrust || echo "/home/$SSH_USER/pmtrust"; }
sudo_() { [ "$SSH_USER" = root ] && echo "" || echo "sudo "; }

cmd=${1:-}; host=${2:-}
[ -n "$cmd" ] && [ -n "$host" ] || { sed -n '2,21p' "$0"; exit 64; }
A=$(addr "$host"); R=$(remote_dir); S=$(sudo_)
T="$SSH_USER@$A"

case "$cmd" in
collect)
    shift 2
    [ -f "$AGENT_DIR/collect.sh" ] || { echo "build the agent first: python3 pmtrust.py agent --out agent-build" >&2; exit 1; }
    log "push agent to $host ($A)"
    ssh $SSH_OPTS "$T" "mkdir -p $R"
    scp $SSH_OPTS -q -r "$AGENT_DIR"/. "$T:$R/"
    extra=""
    if [ "${1:-}" = --hash-list ]; then scp $SSH_OPTS -q "$2" "$T:$R/need-hashes.txt"; extra="--hash-list $R/need-hashes.txt"; fi
    if [ "$host" = tweety ]; then run="${S}/bin/sh $R/collect.sh --out $R/out $extra"
    else run="${S}$R/bin/busybox sh $R/collect.sh --out $R/out $extra"; fi
    log "collect on $host: $run"
    out=$(ssh $SSH_OPTS "$T" "$run" | tee -a "$LOG")
    snap=$(printf '%s\n' "$out" | awk '/^snapshot:/{print $2}')
    sum=$(printf '%s\n' "$out" | awk '/^sha256:/{print $2}')
    mkdir -p snaps
    if [ -n "$S" ]; then ssh $SSH_OPTS "$T" "sudo chown $SSH_USER $snap"; fi
    scp $SSH_OPTS -q "$T:$snap" snaps/
    got=$(sha256sum "snaps/$(basename "$snap")" | cut -d' ' -f1)
    [ "$got" = "$sum" ] || { log "CHECKSUM MISMATCH for $snap ($got != $sum)"; exit 1; }
    log "snapshot saved: snaps/$(basename "$snap") (sha256 $got matches the box)"
    ;;
apply)
    plan=${3:?plan directory}; shift 3
    name=$(basename "$plan")
    if ! ssh $SSH_OPTS "$T" "test -f $R/$name/MANIFEST.sha256"; then
        log "push $plan to $host:$R/"
        scp $SSH_OPTS -q -r "$plan" "$T:$R/"
    fi
    log "apply on $host: apply.sh $*"
    ssh $SSH_OPTS -t "$T" "cd $R/$name && ${S}./bin/busybox sh ./apply.sh $*" | tee -a "$LOG"
    ;;
fetch-evidence)
    mkdir -p "evidence/$host"
    if [ "$host" = tweety ]; then tarc="${S}tar"; else tarc="${S}$R/bin/busybox tar"; fi
    ssh $SSH_OPTS "$T" "$tarc -C /var/lib -cf - pmtrust" | tar -C "evidence/$host" -xf -
    log "evidence for $host in evidence/$host/pmtrust"
    ;;
*) sed -n '2,21p' "$0"; exit 64 ;;
esac
