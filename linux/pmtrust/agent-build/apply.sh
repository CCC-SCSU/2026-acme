#!/bin/sh
# pmtrust apply.sh -- carry out a pmtrust plan on this box (same script for every backend).
#
# Purpose : lay verified files down, quarantine package-manager injection points,
#           then run the now-verified package manager to repair its database
#           (finalize.sh). Every changed path is backed up first.
# Hosts   : daffy elmer marvin taz (apt), foghorn sylvester (rpm), porky (pacman),
#           ysam (nix store repair). tweety and roadrunner are audit-only (no plan).
# Run     : cd /root/pmtrust/plan-<host>-<time>
#           ./bin/busybox sh ./apply.sh                 # DRY RUN (default): checks, shows actions
#           ./bin/busybox sh ./apply.sh --apply         # make the changes
#           ./bin/busybox sh ./apply.sh --verify        # read-only: re-check every verified file
#           ./bin/busybox sh ./apply.sh --rollback /var/lib/pmtrust/run-<time>
#           extra: --workdir DIR  --max-age-hours N (default 48)  --force (wrong host / old plan)
# Revert  : --rollback <workdir> restores backed-up and quarantined files and the package
#           database backup, in reverse order. The workdir and apply.log are incident evidence.
# Limits  : runs on the live box; a kernel-level rootkit can lie to every check here.
set -u
set -f
umask 077

case "$0" in */*) PLAN=${0%/*} ;; *) PLAN=. ;; esac
PLAN=$(cd "$PLAN" && pwd) || exit 1
BB="$PLAN/bin/busybox"
if ! "$BB" true 2>/dev/null; then
    echo "FATAL: $BB missing or not runnable" >&2
    exit 1
fi
PATH=/pmtrust-no-path-use-busybox
export PATH
TAB=$(printf '\t')

MODE=dry
WORK=""
MAXAGE=48
FORCE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --apply) MODE=apply; shift ;;
        --verify) MODE=verify; shift ;;
        --rollback) MODE=rollback; WORK=${2:-}; shift 2 || { echo "--rollback needs a workdir" >&2; exit 64; } ;;
        --workdir) WORK=$2; shift 2 ;;
        --max-age-hours) MAXAGE=$2; shift 2 ;;
        --force) FORCE=1; shift ;;
        -h|--help) "$BB" sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 64 ;;
    esac
done

[ "$("$BB" id -u)" = "0" ] || { echo "FATAL: run as root" >&2; exit 1; }
TS=$("$BB" date -u +%Y%m%dT%H%M%SZ)
LOG=""
CRIT=0; WARN=0; CHANGED=0; SKIPPED=0; FAILED=0; DRIFT=0

log() {
    _l="$("$BB" date -u +%Y-%m-%dT%H:%M:%SZ) $*"
    [ -n "$LOG" ] && printf '%s\n' "$_l" >> "$LOG"
    printf '%s\n' "$*" >&2
}
crit() { CRIT=$((CRIT + 1)); log "[CRIT] $*"; }
warn() { WARN=$((WARN + 1)); log "[WARN] $*"; }
die() { log "[FATAL] $*"; exit 1; }
record() { printf '%s\n' "$*" >> "$WORK/manifest.tsv"; }

exists() { [ -e "$1" ] || [ -L "$1" ]; }

state_of() {   # f:<sha> | l:<target> | d | o | -
    if [ -L "$1" ]; then printf 'l:%s' "$("$BB" readlink "$1")"
    elif [ -f "$1" ]; then printf 'f:%s' "$("$BB" sha256sum "$1" | "$BB" cut -d' ' -f1)"
    elif [ -d "$1" ]; then printf 'd'
    elif [ -e "$1" ]; then printf 'o'
    else printf '%s' '-'
    fi
}

perm_of() { "$BB" stat -c '%a %u %g' "$1" 2>/dev/null; }

# Create missing parent directories one by one so rollback can remove them.
mkparents() {
    _d=${1%/*}
    [ -z "$_d" ] && return 0
    [ -d "$_d" ] && return 0
    mkparents "$_d"
    "$BB" mkdir "$_d" && "$BB" chmod 755 "$_d" && [ "$MODE" = apply ] && record "D${TAB}$_d${TAB}CREATED"
    return 0
}

# The parent of $1 must be a real directory path with no symlink in it now;
# the plan resolved symlinks from the snapshot and refuses to follow new ones.
parent_ok() {
    _d=${1%/*}
    [ -z "$_d" ] && return 0
    [ -d "$_d" ] || return 0
    _r=$("$BB" realpath "$_d" 2>/dev/null)
    [ "$_r" = "$_d" ]
}

payload_of() { _s=$1; printf '%s/payload/%s/%s' "$PLAN" "${_s%"${_s#??}"}" "$_s"; }

backup() {     # copy current $1 into the workdir; echo the backup path or ABSENT
    if exists "$1"; then
        _b="$WORK/backup$1"
        "$BB" mkdir -p "${_b%/*}"
        "$BB" rm -rf "$_b"
        "$BB" cp -a "$1" "$_b" || { echo FAIL; return 1; }
        echo "$_b"
    else
        echo ABSENT
    fi
}

check_plan() {
    cd "$PLAN" || die "cannot cd to $PLAN"
    [ -f MANIFEST.sha256 ] || die "no MANIFEST.sha256 in $PLAN"
    if ! "$BB" sha256sum -c -s MANIFEST.sha256; then
        "$BB" sha256sum -c MANIFEST.sha256 2>&1 | "$BB" grep -v ': OK$' >&2
        die "plan files do not match MANIFEST.sha256 (corrupted or tampered in transit)"
    fi
    PLAN_ID=$("$BB" sha256sum MANIFEST.sha256 | "$BB" cut -d' ' -f1)
    # shellcheck disable=SC1091
    . "$PLAN/plan.env"
    _host=$("$BB" hostname | "$BB" sed 's/[^A-Za-z0-9._-]/_/g')
    if [ "$_host" != "$HOST" ]; then
        [ "$FORCE" = 1 ] || die "plan is for host '$HOST' but this is '$_host' (use --force if renamed)"
        warn "plan is for host '$HOST' but this is '$_host' (--force)"
    fi
    _now=$("$BB" date +%s)
    _age=$(( (_now - CREATED_EPOCH) / 3600 ))
    if [ "$_age" -gt "$MAXAGE" ]; then
        [ "$FORCE" = 1 ] || die "plan is ${_age}h old (limit ${MAXAGE}h); collect a new snapshot or use --force"
        warn "plan is ${_age}h old (--force)"
    fi
    log "plan $PLAN_ID  backend=$BACKEND host=$HOST created=$CREATED snapshot=$SNAPSHOT_DATE actions=$ACTIONS"
    log "Compare the plan id above with the one printed by 'pmtrust plan' on the staging host."
}

# ---------------------------------------------------------------- verify -----
do_verify() {
    _t="${WORK:-/tmp}/pmtrust-verify.$$"
    "$BB" mkdir -p "$_t"
    "$BB" awk -F"$TAB" '$1=="f"{printf "%s%c",$2,0}' "$PLAN/verify.tsv" \
        | "$BB" xargs -0 -r "$BB" sha256sum > "$_t/hash" 2>/dev/null
    "$BB" awk -F"$TAB" '{printf "%s%c",$2,0}' "$PLAN/verify.tsv" \
        | "$BB" xargs -0 -r "$BB" stat -c '%a %u %g %f %n' > "$_t/stat" 2>/dev/null
    "$BB" awk -F"$TAB" '$1=="l"{printf "%s%c",$2,0}' "$PLAN/verify.tsv" \
        | "$BB" xargs -0 -r "$BB" stat -c '%N' > "$_t/link" 2>/dev/null
    "$BB" awk -v H="$_t/hash" -v S="$_t/stat" -v L="$_t/link" -F"$TAB" '
        BEGIN {
            while ((getline line < H) > 0) { h[substr(line, 67)] = substr(line, 1, 64) }
            while ((getline line < S) > 0) {
                n = split(line, a, " "); p = line
                for (i = 1; i <= 4; i++) sub(/^[^ ]* /, "", p)
                st[p] = a[1] " " a[2] " " a[3]; ty[p] = substr(a[4], 1, 1)
            }
            while ((getline line < L) > 0) {
                i = index(line, "\047 -> \047")
                if (i > 0) lk[substr(line, 2, i - 2)] = substr(line, i + 6, length(line) - i - 6)
            }
            c = 0; w = 0; n = 0
        }
        {
            n++; kind = $1; p = $2; want = $3; perm = $4 " " $5 " " $6; lvl = $7; pkg = $8
            msg = ""
            if (!(p in ty)) msg = "missing"
            else if (kind == "f") {
                if (ty[p] != "8") msg = "not a regular file"
                else if (h[p] != want) msg = "content differs from verified package"
                else if (st[p] != perm) msg = "mode/owner " st[p] " != " perm
            } else if (kind == "l") {
                if (ty[p] != "a") msg = "not a symlink"
                else if (lk[p] != want) msg = "symlink -> " lk[p] " (expected " want ")"
            }
            if (msg != "") {
                if (lvl == "C") { c++; print "[CRIT] " p " (" pkg "): " msg }
                else { w++; print "[WARN] " p " (" pkg ", conffile): " msg }
            }
        }
        END { print "VERIFY " n " " c " " w }
    ' "$PLAN/verify.tsv" > "$_t/result"
    "$BB" grep -v '^VERIFY ' "$_t/result" | while IFS= read -r line; do log "$line"; done
    # shellcheck disable=SC2046
    set -- $("$BB" grep '^VERIFY ' "$_t/result")
    V_TOTAL=${2:-0}; V_CRIT=${3:-0}; V_WARN=${4:-0}
    log "verify: $V_TOTAL verified paths checked, $V_CRIT critical, $V_WARN conffile warnings"
    "$BB" rm -rf "$_t"
}

# ---------------------------------------------------------------- actions ----
act_Q() {   # path old why : quarantine exactly the kind of object the snapshot showed
    _p=$1; _was=$2
    if ! exists "$_p"; then SKIPPED=$((SKIPPED + 1)); return 0; fi
    _now=$(state_of "$_p")
    if [ "${_was%%:*}" != "${_now%%:*}" ] && [ "$_was" != "?" ]; then
        log "  skip Q $_p: it is now a ${_now%%:*}, not the ${_was%%:*} the plan saw (already repaired?)"
        SKIPPED=$((SKIPPED + 1)); return 0
    fi
    [ "$MODE" = apply ] || return 0
    _q="$WORK/quarantine$_p"
    "$BB" mkdir -p "${_q%/*}"
    "$BB" rm -rf "$_q"
    if "$BB" mv -f "$_p" "$_q"; then
        record "Q${TAB}$_p${TAB}$_q"; CHANGED=$((CHANGED + 1)); log "  quarantined $_p -> $_q"
    else
        FAILED=$((FAILED + 1)); crit "could not quarantine $_p"
    fi
}

act_F() {   # path sha mode uid gid old why
    _p=$1; _sha=$2; _mode=$3; _uid=$4; _gid=$5
    _src=$(payload_of "$_sha")
    if [ -d "$_p" ] && [ ! -L "$_p" ]; then crit "$_p is a directory; not replacing it"; FAILED=$((FAILED + 1)); return 0; fi
    if ! parent_ok "$_p"; then
        crit "parent of $_p is now a symlink or moved since the snapshot; skipped"; FAILED=$((FAILED + 1)); return 0
    fi
    if [ -f "$_p" ] && [ ! -L "$_p" ]; then
        _cur=$("$BB" sha256sum "$_p" | "$BB" cut -d' ' -f1)
        if [ "$_cur" = "$_sha" ] && [ "$(perm_of "$_p")" = "$_mode $_uid $_gid" ]; then
            SKIPPED=$((SKIPPED + 1)); return 0
        fi
    fi
    [ "$MODE" = apply ] || return 0
    mkparents "$_p"
    _b=$(backup "$_p") || { crit "backup of $_p failed; not replacing it"; FAILED=$((FAILED + 1)); return 0; }
    _tmp="${_p%/*}/.pmtrust-$$.tmp"
    "$BB" rm -f "$_tmp"
    if "$BB" cp "$_src" "$_tmp" && "$BB" chown "$_uid:$_gid" "$_tmp" && "$BB" chmod "$_mode" "$_tmp" \
            && "$BB" mv -fT "$_tmp" "$_p"; then
        record "F${TAB}$_p${TAB}$_b"
        _new=$("$BB" sha256sum "$_p" | "$BB" cut -d' ' -f1)
        if [ "$_new" != "$_sha" ]; then crit "$_p does not hash to the verified value after writing"; FAILED=$((FAILED + 1)); return 0; fi
        CHANGED=$((CHANGED + 1))
    else
        "$BB" rm -f "$_tmp"; crit "could not write $_p"; FAILED=$((FAILED + 1))
    fi
}

act_L() {   # path target uid gid old why
    _p=$1; _tgt=$2; _uid=$3; _gid=$4
    if [ -d "$_p" ] && [ ! -L "$_p" ]; then crit "$_p is a directory; not replacing it"; FAILED=$((FAILED + 1)); return 0; fi
    if ! parent_ok "$_p"; then crit "parent of $_p changed since the snapshot; skipped"; FAILED=$((FAILED + 1)); return 0; fi
    if [ -L "$_p" ] && [ "$("$BB" readlink "$_p")" = "$_tgt" ]; then SKIPPED=$((SKIPPED + 1)); return 0; fi
    [ "$MODE" = apply ] || return 0
    mkparents "$_p"
    _b=$(backup "$_p") || { crit "backup of $_p failed"; FAILED=$((FAILED + 1)); return 0; }
    _tmp="${_p%/*}/.pmtrust-$$.lnk"
    "$BB" rm -f "$_tmp"
    if "$BB" ln -s "$_tgt" "$_tmp" && "$BB" chown -h "$_uid:$_gid" "$_tmp" && "$BB" mv -fT "$_tmp" "$_p"; then
        record "L${TAB}$_p${TAB}$_b"; CHANGED=$((CHANGED + 1))
    else
        "$BB" rm -f "$_tmp"; crit "could not create symlink $_p"; FAILED=$((FAILED + 1))
    fi
}

act_D() {   # path mode uid gid old why
    _p=$1; _mode=$2; _uid=$3; _gid=$4
    if [ -d "$_p" ] && [ ! -L "$_p" ]; then
        _cur=$(perm_of "$_p")
        [ "$_cur" = "$_mode $_uid $_gid" ] && { SKIPPED=$((SKIPPED + 1)); return 0; }
        [ "$MODE" = apply ] || return 0
        record "DM${TAB}$_p${TAB}$_cur"
    else
        if exists "$_p"; then crit "$_p exists and is not a directory; skipped"; FAILED=$((FAILED + 1)); return 0; fi
        [ "$MODE" = apply ] || return 0
        mkparents "$_p"
        "$BB" mkdir "$_p" || { crit "could not create $_p"; FAILED=$((FAILED + 1)); return 0; }
        record "D${TAB}$_p${TAB}CREATED"
    fi
    "$BB" chown "$_uid:$_gid" "$_p" && "$BB" chmod "$_mode" "$_p"
    CHANGED=$((CHANGED + 1))
}

act_T() {   # path why : back up a whole tree (package database) before finalize
    _p=$1
    [ "$MODE" = apply ] || return 0
    if ! exists "$_p"; then record "TA${TAB}$_p"; return 0; fi     # rollback removes what finalize creates
    _tf="$WORK/tree$(printf '%s' "$_p" | "$BB" tr '/' '_').tar"
    if "$BB" tar -cf "$_tf" -C / "${_p#/}"; then
        record "T${TAB}$_p${TAB}$_tf"; log "  backed up $_p -> $_tf"
    else
        die "could not back up $_p; stopping before any change to it"
    fi
}

under_quarantine() {   # dry run: is $1 inside something an earlier action quarantines?
    for _q in $QLIST; do
        case "$1" in "$_q"|"$_q"/*) return 0 ;; esac
    done
    return 1
}

run_actions() {
    _n=0
    QLIST=""
    while IFS="$TAB" read -r op p a b c d e f; do
        _n=$((_n + 1))
        [ -n "$op" ] || continue
        if [ "$MODE" = dry ]; then
            [ "$op" = Q ] && QLIST="$QLIST $p"
            if [ "$op" != Q ] && under_quarantine "$p"; then
                log "  would $op $p  (recreated after the quarantine above)"
                continue
            fi
        fi
        case "$op" in
            Q) _old=$a; _why=$b ;;
            F) _old=$e; _why=$f ;;
            L) _old=$d; _why=$e ;;
            D) _old=$d; _why=$e ;;
            T) _old=""; _why=$a ;;
            *) crit "unknown action '$op' on line $_n"; continue ;;
        esac
        [ "$MODE" = apply ] && [ "$op" = Q ] && QLIST="$QLIST $p"
        case "$op" in Q) _want=-;; F) _want="f:$a";; L) _want="l:$a";; D) _want=d;; *) _want="";; esac
        if [ -n "$_old" ] && [ "$op" != T ] && ! { [ "$op" != Q ] && under_quarantine "$p"; }; then
            _now=$(state_of "$p")
            case "$_old" in
                f:\?) ;;
                *) if [ "$_now" != "$_old" ] && [ "$_now" != "$_want" ]; then
                       DRIFT=$((DRIFT + 1))
                       warn "drift: $p changed since the snapshot (was ${_old%%:*}, now ${_now%%:*}); the verified version is still applied"
                   fi ;;
            esac
        fi
        [ "$MODE" = dry ] && log "  would $op $p  ($_why)"
        case "$op" in
            Q) act_Q "$p" "$a" ;;
            F) act_F "$p" "$a" "$b" "$c" "$d" ;;
            L) act_L "$p" "$a" "$b" "$c" ;;
            D) act_D "$p" "$a" "$b" "$c" ;;
            T) act_T "$p" ;;
        esac
    done < "$PLAN/actions.tsv"
}

# ---------------------------------------------------------------- rollback ---
do_rollback() {
    [ -n "$WORK" ] && [ -f "$WORK/manifest.tsv" ] || die "no manifest.tsv in '$WORK'"
    LOG="$WORK/rollback-$TS.log"
    log "rolling back $WORK (reverse order)"
    # shellcheck disable=SC1091
    [ -f "$PLAN/finalize.sh" ] && . "$PLAN/finalize.sh"
    if type pm_prepare >/dev/null 2>&1; then pm_prepare; fi
    _conf="$WORK/rollback-conflicts-$TS"
    "$BB" tac "$WORK/manifest.tsv" | while IFS="$TAB" read -r op p a b c; do
        case "$op" in
            F|L|RM)
                if [ "$a" = ABSENT ]; then
                    "$BB" rm -f "$p" && log "  removed $p (did not exist before)"
                elif [ -n "$a" ] && exists "$a"; then
                    "$BB" rm -f "$p.pmtrust-rb"
                    "$BB" cp -a "$a" "$p.pmtrust-rb" && "$BB" mv -fT "$p.pmtrust-rb" "$p" && log "  restored $p"
                fi ;;
            Q)
                if exists "$a"; then
                    if exists "$p"; then "$BB" mkdir -p "$_conf${p%/*}"; "$BB" mv -f "$p" "$_conf$p"; fi
                    "$BB" mkdir -p "${p%/*}"
                    "$BB" cp -a "$a" "$p" && log "  restored quarantined $p"
                fi ;;
            D)  [ "$a" = CREATED ] && { "$BB" rmdir "$p" 2>/dev/null && log "  removed created dir $p" || log "  left non-empty dir $p"; } ;;
            DM) "$BB" chown "$b:$c" "$p" && "$BB" chmod "$a" "$p" && log "  restored perms of $p ($a $b:$c)" ;;
            T)  if [ -f "$a" ]; then
                    "$BB" rm -rf "$p.pmtrust-rb-old"
                    "$BB" mv -f "$p" "$p.pmtrust-rb-old" && "$BB" tar -xpf "$a" -C / \
                        && "$BB" rm -rf "$p.pmtrust-rb-old" && log "  restored tree $p from $a"
                fi ;;
            MV) exists "$a" && "$BB" mv -f "$a" "$p" && log "  moved $a back to $p" ;;
            TA) exists "$p" && "$BB" rm -rf "$p" && log "  removed $p (created by finalize)" ;;
        esac
    done
    if type pm_cleanup >/dev/null 2>&1; then pm_cleanup; fi
    log "rollback finished. Files changed by the package manager outside the plan (e.g. files an upgrade removed) are not restored; see $WORK/apply.log"
}

# ---------------------------------------------------------------- main -------
if [ "$MODE" = rollback ]; then
    do_rollback
    exit 0
fi

check_plan

if [ "$MODE" = verify ]; then
    do_verify
    [ "$V_CRIT" -gt 0 ] && exit 2
    exit 0
fi

if [ "$MODE" = apply ]; then
    [ -n "$WORK" ] || WORK="/var/lib/pmtrust/run-$TS"
    "$BB" mkdir -p "$WORK" && "$BB" chmod 700 "$WORK" || die "cannot create $WORK"
    LOG="$WORK/apply.log"
    : > "$WORK/manifest.tsv"
    "$BB" cp "$PLAN/plan.env" "$PLAN/report.txt" "$WORK/" 2>/dev/null
    printf '%s\n' "$PLAN_ID" > "$WORK/plan-id"
    log "APPLY plan $PLAN_ID on $HOST, workdir $WORK"
    _free=$("$BB" df -k "$WORK" 2>/dev/null | "$BB" awk 'NR==2{print $4}')
    _need=$("$BB" du -sk "$PLAN/payload" 2>/dev/null | "$BB" cut -f1)
    if [ -n "$_free" ] && [ -n "$_need" ] && [ $((_need * 3)) -gt "$_free" ]; then
        die "not enough free space in $WORK for backups (need ~$((_need * 3)) KiB, have $_free KiB)"
    fi
else
    log "DRY RUN: nothing will be changed (use --apply)."
fi

# shellcheck disable=SC1091
. "$PLAN/finalize.sh"
if [ "$MODE" = apply ] && type pm_prepare >/dev/null 2>&1; then pm_prepare; fi

log "== actions"
run_actions

if [ "$MODE" = apply ]; then
    if [ "$CHANGED" -gt 0 ] || pm_needs_finalize; then
        log "== finalize: running the verified package manager ($BACKEND)"
        pm_finalize
    else
        log "== finalize: not needed (nothing changed and the database already matches)"
    fi
    if type pm_cleanup >/dev/null 2>&1; then pm_cleanup; fi
    log "== verify after apply"
    do_verify
else
    # Never execute anything from the box in a dry run: its package manager is
    # not verified yet. Report from the plan instead.
    [ -n "${FINALIZE_PKGS:-}" ] && log "finalize would run the verified package manager for: $FINALIZE_PKGS"
    [ -n "${RESTARTS:-}" ] && log "services the package scripts may restart: $RESTARTS"
fi

log ""
log "summary: mode=$MODE changed=$CHANGED already-correct=$SKIPPED failed=$FAILED drift=$DRIFT crit=$CRIT warn=$WARN"
if [ "$MODE" = apply ]; then
    log "workdir: $WORK   log: $LOG"
    log "rollback: $BB sh $PLAN/apply.sh --rollback $WORK"
    [ "$FAILED" -gt 0 ] && exit 2
    [ "${V_CRIT:-0}" -gt 0 ] && exit 2
fi
[ "$CRIT" -gt 0 ] && exit 2
exit 0
