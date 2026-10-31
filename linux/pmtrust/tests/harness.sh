#!/bin/bash
# Test helpers: run the on-box agent inside a chroot that stands in for a box.
# The chroot gets its own UTS namespace (hostname) and mount namespace.
AGENT=${AGENT:-/srv/t/agent}
PM=${PM:-/home/claude/pmtrust/pmtrust.py}

collect() {   # collect TARGET HOSTNAME  -> prints snapshot path on stdout
    local T=$1 H=$2
    rm -rf "$T/root/pmtrust"; mkdir -p "$T/root/pmtrust"; cp -a "$AGENT/." "$T/root/pmtrust/"
    unshare -u -m sh -c "hostname $H; mount -t proc proc $T/proc; mount --bind /dev $T/dev; chroot $T /root/pmtrust/bin/busybox sh /root/pmtrust/collect.sh ${COLLECT_ARGS:-}" >&2
    ls -t "$T"/root/pmtrust/out/snap-"$H"-*.tar.gz | head -1
}

apply_in() {  # apply_in TARGET HOSTNAME PLANDIR [apply.sh args...]
    local T=$1 H=$2 P=$3; shift 3
    rm -rf "$T/root/pmtrust/plan"; cp -a "$P" "$T/root/pmtrust/plan"
    unshare -u -m sh -c "hostname $H; mount -t proc proc $T/proc; mount --bind /dev $T/dev; \
        chroot $T /root/pmtrust/plan/bin/busybox sh /root/pmtrust/plan/apply.sh $*"
}

markers() {   # list attack marker files inside a target
    find "$1" -xdev -maxdepth 1 -name 'PWNED_*' -printf '%f\n' 2>/dev/null | sort
}
