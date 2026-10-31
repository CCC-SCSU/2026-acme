#!/bin/sh
# pmtrust collect.sh -- READ-ONLY snapshot of a box for the staging-side audit.
#
# Purpose : record file metadata + SHA256 of system directories, and copy the
#           package database and config files, so the trusted staging host can
#           audit the package manager without trusting anything on this box.
#           Runs nothing from the box except the kernel: on Linux every tool is
#           the bundled static busybox. No package-manager command is executed.
# Hosts   : Linux  - daffy elmer marvin taz (apt), foghorn sylvester (rpm),
#                    porky (pacman), ysam (nix), roadrunner (tce)
#           FreeBSD - tweety (OPNsense, audit only; uses the native /bin/sh tools)
# Run     : Linux : /root/pmtrust/bin/busybox sh /root/pmtrust/collect.sh
#           tweety: /bin/sh /root/pmtrust/collect.sh
#           options: --out DIR (default <agent>/out)  --hash-list FILE (extra
#           paths to hash, one per line, e.g. nix store paths from `pmtrust plan`)
#           --max-hash-mb N (default 64)  --quick (skip hashing /usr/share)
# Output  : <out>/snap-<host>-<UTCtime>.tar.gz  -> copy it to the staging host.
# Revert  : nothing to revert; only <out> is written. Secrets (shadow, private
#           keys, keytabs, *secret*, debian.cnf, OPNsense /conf) are hashed but
#           never copied.
set -u
set -f            # no globbing: find patterns live in unquoted variables
umask 077

HERE=${0%/*}
[ "$HERE" = "$0" ] && HERE=.
# Never run a bare command on Linux: busybox could fall back to the box's own
# (possibly trojaned) binaries. The OS is read with the bundled busybox if present.
if [ -x "$HERE/bin/busybox" ] && "$HERE/bin/busybox" true 2>/dev/null; then
    OS=$("$HERE/bin/busybox" uname -s)
else
    OS=$(/usr/bin/uname -s 2>/dev/null || /rescue/uname -s 2>/dev/null || echo unknown)
fi
OUT=""
HASH_LIST=""
MAXMB=64
QUICK=0
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT=$2; shift 2 ;;
        --hash-list) HASH_LIST=$2; shift 2 ;;
        --max-hash-mb) MAXMB=$2; shift 2 ;;
        --quick) QUICK=1; shift ;;
        -h|--help) while IFS= read -r l; do case "$l" in '#'*) printf '%s\n' "$l" ;; *) break ;; esac; done < "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 64 ;;
    esac
done

if [ "$OS" = "Linux" ]; then
    BB="$HERE/bin/busybox"
    if ! "$BB" true 2>/dev/null; then
        echo "FATAL: $BB is missing or not runnable; copy the whole agent directory" >&2
        exit 1
    fi
    T() { "$BB" "$@"; }
    PATH=/pmtrust-no-path-use-busybox; export PATH
    STATFMT_ARGS="-c"; STATFMT='%f %u %g %s %n'; LINKFMT='%N'
    HASHCMD="$BB sha256sum"
elif [ "$OS" = "FreeBSD" ]; then
    BB=""
    T() { "$@"; }
    STATFMT_ARGS="-f"; STATFMT='%Xp %u %g %z %N'; LINKFMT='%N	%Y'
    HASHCMD="sha256 -r"
else
    echo "FATAL: unsupported OS $OS" >&2; exit 1
fi

[ "$(T id -u)" = "0" ] || { echo "FATAL: run as root" >&2; exit 1; }
HOST=$(T hostname 2>/dev/null | T sed 's/[^A-Za-z0-9._-]/_/g')
TS=$(T date -u +%Y%m%dT%H%M%SZ)
[ -n "$OUT" ] || OUT="$HERE/out"
SNAP="$OUT/snap-$HOST-$TS"
T mkdir -p "$SNAP"
LOG="$SNAP/collect.log"
log() { printf '%s %s\n' "$(T date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | T tee -a "$LOG" >&2; }

NL='
'
MAXC=$((MAXMB * 1024 * 1024))

# Roots that hold package-managed system files. Data directories (databases,
# containers, logs, home) are deliberately not walked.
LIST_ROOTS=""
for d in /bin /sbin /lib /lib32 /lib64 /libx32 /usr /etc /boot /opt /root /var/lib/dpkg \
         /var/lib/rpm /var/lib/pacman /var/db/pkg /usr/local /nix/var/nix/profiles \
         /run/current-system /conf /usr/local/tce.installed /tmp/tcloop; do
    [ -e "$d" ] || [ -L "$d" ] || continue
    LIST_ROOTS="$LIST_ROOTS $d"
done

log "pmtrust collect on $HOST ($OS), roots:$LIST_ROOTS"

# ---- metadata -------------------------------------------------------------
{
    echo "collector=pmtrust-collect/2"
    echo "os=$OS"
    echo "hostname=$HOST"
    echo "date_utc=$TS"
    echo "uname=$(T uname -a)"
    echo "max_hash_bytes=$MAXC"
    echo "quick=$QUICK"
    if [ -n "$BB" ]; then echo "busybox_sha256=$($HASHCMD "$BB" | T cut -d' ' -f1)"; fi
    echo "roots=$LIST_ROOTS"
} > "$SNAP/meta.txt"

# ---- file listing (type/mode, owner, size, path) --------------------------
# Paths containing a newline cannot be represented line-by-line; they are
# listed separately (NUL separated) because they are suspicious by themselves.
AGENT_DIR=$(cd "$HERE" && pwd)
PRUNE="-path /proc -o -path /sys -o -path /dev -o -path /run/user -o -path /tmp/tce -o -path $AGENT_DIR -o -path /root/pmtrust"
log "listing files"
# shellcheck disable=SC2086
T find $LIST_ROOTS -xdev \( $PRUNE \) -prune -o -name "*${NL}*" -print0 > "$SNAP/weird.bin" 2>/dev/null
# shellcheck disable=SC2086
T find $LIST_ROOTS -xdev \( $PRUNE \) -prune -o \( -type f -o -type d -o -type l \) \
    ! -name "*${NL}*" -exec $BB stat $STATFMT_ARGS "$STATFMT" {} + > "$SNAP/fs.txt" 2>>"$LOG"
# shellcheck disable=SC2086
T find $LIST_ROOTS -xdev \( $PRUNE \) -prune -o -type l ! -name "*${NL}*" \
    -exec $BB stat $STATFMT_ARGS "$LINKFMT" {} + > "$SNAP/links.txt" 2>>"$LOG"
log "listed $(T wc -l < "$SNAP/fs.txt") entries"

# ---- content hashes ---------------------------------------------------------
HPRUNE="-path $AGENT_DIR -o -path /root/pmtrust -o "'-path /usr/share/doc -o -path /usr/share/man -o -path /usr/share/info -o -path /usr/share/locale -o -path /usr/share/help -o -path /usr/share/icons -o -path /usr/lib/firmware -o -path /usr/lib/modules -o -path /lib/modules -o -path /lib/firmware -o -path /usr/src -o -path /boot -o -path /proc -o -path /sys -o -path /dev -o -path /tmp/tce'
[ "$QUICK" = 1 ] && HPRUNE="$HPRUNE -o -path /usr/share"
log "hashing files up to $MAXMB MiB (pruned: docs, locales, firmware, modules, /boot)"
# shellcheck disable=SC2086
T find $LIST_ROOTS -xdev \( $HPRUNE \) -prune -o -type f -size -"$MAXC"c ! -name "*${NL}*" \
    -exec $HASHCMD {} + > "$SNAP/sha256.txt" 2>>"$LOG"
if [ -n "$HASH_LIST" ] && [ -f "$HASH_LIST" ]; then
    log "hashing extra paths from $HASH_LIST"
    while IFS= read -r p; do
        [ -n "$p" ] && [ -e "$p" ] || continue
        T find "$p" \( -type f -o -type d -o -type l \) ! -name "*${NL}*" \
            -exec $BB stat $STATFMT_ARGS "$STATFMT" {} + >> "$SNAP/fs.txt" 2>>"$LOG"
        T find "$p" -type l ! -name "*${NL}*" \
            -exec $BB stat $STATFMT_ARGS "$LINKFMT" {} + >> "$SNAP/links.txt" 2>>"$LOG"
        T find "$p" -type f ! -name "*${NL}*" -exec $HASHCMD {} + >> "$SNAP/sha256.txt" 2>>"$LOG"
    done < "$HASH_LIST"
fi
log "hashed $(T wc -l < "$SNAP/sha256.txt") files"

# ---- copied files (configs + package databases), secrets excluded -----------
SECRET='-name shadow -o -name shadow- -o -name gshadow -o -name gshadow- -o -name *_key -o -name *.key -o -name *.keytab -o -name *secret* -o -name debian.cnf -o -name opasswd -o -name *.psk -o -name id_rsa -o -name id_ed25519 -o -name id_ecdsa -o -name *history -o -path /etc/ssl/private/* -o -path /etc/pki/tls/private/* -o -path /etc/NetworkManager/system-connections/* -o -path /etc/wireguard/* -o -path /conf/*'
log "copying configuration and package databases (secrets excluded)"
{
    for d in /etc /usr/local/etc /root/.config/nix; do
        [ -d "$d" ] || continue
        # shellcheck disable=SC2086
        T find "$d" -xdev \( $SECRET \) -prune -o -type f -size -1048577c -print0 2>/dev/null
    done
    T find /root -xdev -maxdepth 1 \( $SECRET \) -prune -o -type f -name '.*' -size -1048577c -print0 2>/dev/null
    for d in /var/lib/dpkg /var/lib/rpm /usr/lib/sysimage/rpm /var/lib/pacman/local \
             /nix/var/nix/db /var/db/pkg /usr/local/tce.installed /usr/share/libalpm/hooks \
             /usr/lib/rpm/macros.d /usr/lib/rpm/macros /usr/lib/rpm/rpmrc /boot/loader.conf \
             /boot/loader.conf.d /usr/lib/os-release /etc/os-release /usr/local/etc/pkg.conf; do
        [ -e "$d" ] || continue
        T find "$d" -xdev -type f -size -268435457c ! -name "*${NL}*" -print0 2>/dev/null
    done
    # Python start-up hooks run inside dnf (and anything else written in Python).
    set +f
    for d in /usr/lib/python3* /usr/lib64/python3* /usr/local/lib/python3* /usr/local/lib64/python3*; do
        set -f
        [ -d "$d" ] || continue
        T find "$d" -xdev -maxdepth 2 \( -name '*.pth' -o -name 'sitecustomize.py' -o -name 'usercustomize.py' \) \
            -type f -print0 2>/dev/null
    done
    # Tiny Core persistence points.
    for f in /opt/bootlocal.sh /opt/bootsync.sh /opt/shutdown.sh /opt/.filetool.lst /opt/.xfiletool.lst \
             /opt/tcemirror; do
        [ -f "$f" ] && printf '%s\0' "$f"
    done
} | T cpio -o -H newc -0 2>/dev/null | T gzip -c > "$SNAP/files.cpio.gz"

# Config files that are symlinks into places not copied above (NixOS /etc -> /etc/static -> /nix/store):
# copy their dereferenced content under the link's own name.
{
    for f in /etc/nix/nix.conf /etc/nix/nix.custom.conf /etc/nix/registry.json /etc/os-release /etc/pacman.conf \
             /etc/environment /etc/profile /etc/ld.so.preload /etc/ld.so.conf; do
        [ -L "$f" ] && [ -f "$f" ] && printf '%s\0' "$f"
    done
} | T cpio -o -H newc -0 -L 2>/dev/null | T gzip -c > "$SNAP/deref.cpio.gz"

# ---- runtime facts (read-only) ----------------------------------------------
[ -r /proc/mounts ] && T cat /proc/mounts > "$SNAP/mounts.txt" 2>/dev/null
[ -r /proc/cmdline ] && T cat /proc/cmdline > "$SNAP/cmdline.txt" 2>/dev/null
if [ "$OS" = "Linux" ]; then
    set +f
    for b in /sys/block/loop*/loop/backing_file; do
        set -f
        [ -r "$b" ] || continue
        printf '%s\t%s\n' "${b%/loop/backing_file}" "$(T cat "$b")"
    done > "$SNAP/loops.txt" 2>/dev/null
    # Tiny Core: extension store and the backup archive restored at boot.
    TCEDIR=""
    [ -r /opt/.tce_dir ] && TCEDIR=$(T cat /opt/.tce_dir)
    [ -z "$TCEDIR" ] && [ -L /etc/sysconfig/tcedir ] && TCEDIR=$(T readlink /etc/sysconfig/tcedir)
    if [ -n "$TCEDIR" ] && [ -d "$TCEDIR" ]; then
        echo "$TCEDIR" > "$SNAP/tcedir.txt"
        T find "$TCEDIR" -maxdepth 2 -type f \( -name '*.tcz' -o -name '*.lst' -o -name '*.md5.txt' -o -name '*.dep' -o -name 'mydata.tgz' \) \
            -exec $HASHCMD {} + > "$SNAP/tce-sha256.txt" 2>/dev/null
        # Tiny Core publishes md5 only: record md5 of every extension (and boot images) for baseline comparison
        T find "$TCEDIR" -maxdepth 2 -type f -name '*.tcz' -exec "$BB" md5sum {} + > "$SNAP/tce-md5.txt" 2>/dev/null
        T find "$TCEDIR/.." -maxdepth 2 -path '*/boot/*' -name '*.gz' -exec "$BB" md5sum {} + >> "$SNAP/tce-md5.txt" 2>/dev/null
        T find "$TCEDIR" -maxdepth 2 -type f \( -name '*.md5.txt' -o -name '*.lst' -o -name '*.dep' \) \
            -print0 2>/dev/null | T cpio -o -H newc -0 2>/dev/null | T gzip -c > "$SNAP/tce-files.cpio.gz"
        for m in "$TCEDIR/mydata.tgz" "$TCEDIR/../mydata.tgz"; do
            [ -f "$m" ] && T gzip -dc "$m" | T tar -tvf - > "$SNAP/mydata-list.txt" 2>/dev/null && break
        done
    fi
fi

log "packing snapshot"
# busybox tar -z would exec an external gzip by name; pipe through busybox gzip instead.
if ! T tar -cf - -C "$OUT" "snap-$HOST-$TS" | T gzip -c > "$SNAP.tar.gz" || [ ! -s "$SNAP.tar.gz" ]; then
    echo "FATAL: could not pack $SNAP.tar.gz (left $SNAP for inspection)" >&2
    exit 1
fi
T rm -rf "$SNAP"
SUM=$($HASHCMD "$SNAP.tar.gz" | T cut -d' ' -f1)
echo "snapshot: $SNAP.tar.gz"
echo "sha256:   $SUM"
echo "Copy it to the staging host, e.g.: scp root@<box>:$SNAP.tar.gz ."
