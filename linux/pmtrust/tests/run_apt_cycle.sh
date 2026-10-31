#!/bin/bash
# Full attack cycle for the apt backend on a disposable chroot (skill section 6).
# Usage: run_apt_cycle.sh CLEAN_ROOT HOSTNAME   (e.g. /srv/t/noble-upd marvin)
set -uo pipefail
CLEAN=$1; H=$2
W=/srv/t/cycle-$H
KEY="--keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg --expect-fpr F6ECB3762474EDA9D21B7022871920D1991BC93C"
. /home/claude/pmtrust/tests/harness.sh
PASS=0; FAIL=0
ok()   { echo "PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "FAIL  $*"; FAIL=$((FAIL+1)); }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
plan() { python3 "$PM" plan --snapshot "$1" --out "$2" --agent "$AGENT" $KEY --cache /srv/t/cache "${@:3}" > "$2.out" 2>&1; }

rm -rf "$W"; mkdir -p "$W"
cp -a "$CLEAN" "$W/atk"
bash /home/claude/pmtrust/tests/plant_apt.sh "$W/atk" >/dev/null 2>&1
cp -a "$W/atk" "$W/pristine"

S=$(collect "$W/atk" "$H" 2>/dev/null)
check "collect fires no planted attack" '[ -z "$(markers $W/atk)" ]'
plan "$S" "$W/plan"; rc=$?
check "plan exits 2 (critical findings)" '[ $rc = 2 ]'
R="$W/plan/report.txt"
for pat in "ld.so.preload is active" "/usr/bin/dpkg (dpkg): content differs" "/usr/bin/gpgv (gpgv): content differs" \
           "coreutils.md5sums differs" "ubuntu-archive-keyring.gpg (ubuntu-keyring): content differs" \
           "trusted.gpg.d/evil.gpg" "dpkg.prerm" "libc6:amd64.postrm differs" "dpkg.cfg.d/zz-evil" \
           "99evil" "70debconf (modified conffile)" "diversion /usr/bin/apt-get" "stat-override 'root root 4755" \
           "sources.list.d/evil.list" "methods/evil" "policy-rc.d exists" "/usr/local/sbin/dpkg shadows" \
           "/opt/evil/lib/libz.so.1" "profile.d/zz-evil.sh" "/usr/share/dpkg (dpkg) is a directory" \
           "ca-certificates.postinst differs" "(liblzma5): content differs" ".dpkg.real is not owned"; do
    check "reported: $pat" 'grep -qF -- "$pat" "$R"'
done
apply_in "$W/atk" "$H" "$W/plan" > "$W/dry.out" 2>&1
check "dry run fires nothing and changes nothing" '[ -z "$(markers $W/atk)" ] && diff -rq --no-dereference $W/atk/usr $W/pristine/usr >/dev/null'
apply_in "$W/atk" "$H" "$W/plan" --apply > "$W/apply.out" 2>&1; rc=$?
check "apply exits 0" '[ $rc = 0 ]'
check "apply fires no planted attack" '[ -z "$(markers $W/atk)" ]'
check "post-apply verify: 0 critical" 'grep -q "verify: .* 0 critical" $W/apply.out'
WORKDIR=$(grep -o '/var/lib/pmtrust/run-[0-9TZ]*' "$W/apply.out" | head -1)

# core files byte-identical to the clean tree (paths from verify.tsv, hashed inside each root)
awk -F'\t' '$1=="f" && $7=="C"{print $2}' "$W/plan/verify.tsv" > "$W/paths"
cp "$W/paths" "$W/atk/tmp/paths"; cp "$W/paths" "$CLEAN/tmp/paths"; cp "$AGENT/bin/busybox" "$CLEAN/tmp/busybox"
chroot "$W/atk" /root/pmtrust/plan/bin/busybox sh -c 'tr "\n" "\0" < /tmp/paths | /root/pmtrust/plan/bin/busybox xargs -0 /root/pmtrust/plan/bin/busybox sha256sum' > "$W/h.atk" 2>&1
chroot "$CLEAN" /tmp/busybox sh -c 'tr "\n" "\0" < /tmp/paths | /tmp/busybox xargs -0 /tmp/busybox sha256sum' > "$W/h.clean" 2>&1
rm -f "$CLEAN/tmp/paths" "$CLEAN/tmp/busybox"
check "verified files byte-identical to the clean tree ($(wc -l < $W/paths) files)" 'cmp -s $W/h.atk $W/h.clean'
awk -F'\t' '{print $8}' "$W/plan/verify.tsv" | sort -u > "$W/atk/tmp/pkgs"
unshare -m sh -c "mount -t proc proc $W/atk/proc; chroot $W/atk sh -c 'xargs /usr/bin/dpkg --verify < /tmp/pkgs'" > "$W/dpkg-verify.out" 2>&1
check "dpkg --verify covered $(wc -l < $W/atk/tmp/pkgs) verified packages" '[ $(wc -l < $W/atk/tmp/pkgs) -gt 20 ]'
check "dpkg --verify (now-verified dpkg) clean except conffiles" '! grep -v " c /" $W/dpkg-verify.out | grep -q .'

apply_in "$W/atk" "$H" "$W/plan" --apply > "$W/apply2.out" 2>&1
check "second apply is a no-op" 'grep -q "changed=0 " $W/apply2.out && grep -q "finalize: not needed" $W/apply2.out'
S2=$(collect "$W/atk" "$H" 2>/dev/null)
plan "$S2" "$W/plan2"
check "re-plan after repair has 0 actions" 'grep -q "(0 actions, 0 packages" $W/plan2.out'
check "report-only findings still listed (PATH shadow, loader dir, profile)" 'grep -q "usr/local/sbin/dpkg shadows" $W/plan2/report.txt && grep -q "opt/evil/lib/libz.so.1" $W/plan2/report.txt && grep -q "profile.d/zz-evil.sh" $W/plan2/report.txt'

# rollback restores the attacked state exactly
cp -a "$W/pristine" "$W/rb"
collect "$W/rb" "$H" >/dev/null 2>&1
apply_in "$W/rb" "$H" "$W/plan" --apply > "$W/rb-apply.out" 2>&1
RBW=$(grep -o '/var/lib/pmtrust/run-[0-9TZ]*' "$W/rb-apply.out" | head -1)
unshare -u -m sh -c "hostname $H; chroot $W/rb /root/pmtrust/plan/bin/busybox sh /root/pmtrust/plan/apply.sh --rollback $RBW" > "$W/rollback.out" 2>&1
diff -r --no-dereference -q "$W/rb" "$W/pristine" 2>/dev/null | grep -vE "(/root/pmtrust|/var/lib/pmtrust|rb/root: pmtrust|rb/var/lib: pmtrust|/proc|/dev|/var/log)" > "$W/rollback.diff"
check "rollback restores the attacked tree exactly" '[ ! -s $W/rollback.diff ]'
check "rollback fires no planted attack" '[ -z "$(markers $W/rb)" ]'

echo "== $H: $PASS passed, $FAIL failed (details in $W)"
[ "$FAIL" = 0 ]
