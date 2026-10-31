#!/bin/bash
# Full attack cycle for the rpm backend on the SYNTHETIC Rocky root (skill section 6).
set -uo pipefail
CLEAN=/srv/t/rocky-clean; H=${1:-foghorn}
W=/srv/t/cycle-$H
KEY="--rpm-repo file:///srv/t/rocky/repo --keyring /srv/t/rocky/key.asc --expect-fpr $(cat /srv/t/rocky/fpr)"
. /home/claude/pmtrust/tests/harness.sh
PASS=0; FAIL=0
ok()   { echo "PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "FAIL  $*"; FAIL=$((FAIL+1)); }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
plan() { python3 "$PM" plan --snapshot "$1" --out "$2" --agent "$AGENT" $KEY "${@:3}" > "$2.out" 2>&1; }
rm -rf "$W"; mkdir -p "$W"
cp -a "$CLEAN" "$W/atk"; bash /home/claude/pmtrust/tests/plant_rpm.sh "$W/atk" >/dev/null 2>&1; cp -a "$W/atk" "$W/pristine"
S=$(collect "$W/atk" "$H" 2>/dev/null)
check "collect fires no planted attack" '[ -z "$(markers $W/atk)" ]'
plan "$S" "$W/plan"; rc=$?
check "plan exits 2 (critical findings)" '[ $rc = 2 ]'
R="$W/plan/report.txt"
for pat in "ld.so.preload is active" "/usr/bin/rpm (rpm): content differs" "etc/rpm/macros.zzevil" \
           "macros.transaction_evil" "rpm-plugins/evil.so" "sitecustomize.py" "dnf-plugins/evil.py" \
           "gpgcheck=0" "rpmdb entry for rpm-4.16.1.3-29.el9.x86_64 differs" \
           "rpmdb entry for systemd-ft-252-32.el9.x86_64 differs" "not pinned" "(rpm-libs): content differs" \
           ".rpm.real is not owned"; do
    check "reported: $pat" 'grep -qF -- "$pat" "$R"'
done
apply_in "$W/atk" "$H" "$W/plan" > "$W/dry.out" 2>&1
check "dry run fires nothing and changes nothing" '[ -z "$(markers $W/atk)" ] && diff -rq --no-dereference $W/atk/usr $W/pristine/usr >/dev/null'
apply_in "$W/atk" "$H" "$W/plan" --apply > "$W/apply.out" 2>&1; rc=$?
check "apply exits 0" '[ $rc = 0 ]'
check "apply fires no planted attack (old %preun/%postun, triggers, file triggers, plugin, macro)" '[ -z "$(markers $W/atk)" ]'
check "post-apply verify: 0 critical" 'grep -q "verify: .* 0 critical" $W/apply.out'
awk -F'\t' '$1=="f" && $7=="C"{print $2}' "$W/plan/verify.tsv" > "$W/paths"
cp "$W/paths" "$W/atk/tmp/paths"; cp "$W/paths" "$CLEAN/tmp/paths"; cp "$AGENT/bin/busybox" "$CLEAN/tmp/busybox"
chroot "$W/atk" /root/pmtrust/plan/bin/busybox sh -c 'tr "\n" "\0" < /tmp/paths | /root/pmtrust/plan/bin/busybox xargs -0 /root/pmtrust/plan/bin/busybox sha256sum' > "$W/h.atk" 2>&1
chroot "$CLEAN" /tmp/busybox sh -c 'tr "\n" "\0" < /tmp/paths | /tmp/busybox xargs -0 /tmp/busybox sha256sum' > "$W/h.clean" 2>&1
rm -f "$CLEAN/tmp/paths" "$CLEAN/tmp/busybox"
check "verified files byte-identical to the clean tree ($(wc -l < $W/paths) files)" 'cmp -s $W/h.atk $W/h.clean'
awk -F'\t' '{print $8}' "$W/plan/verify.tsv" | sort -u > "$W/atk/tmp/pkgs"
unshare -m sh -c "mount -t proc proc $W/atk/proc; chroot $W/atk sh -c '/usr/bin/rpm --dbpath /var/lib/rpm -V \$(cat /tmp/pkgs)'" > "$W/rpmV.out" 2>&1
check "rpm -V (now-verified rpm and rpmdb) clean except config files" '! grep -vE " c /| /(proc|dev|sys)$" $W/rpmV.out | grep -q .'
check "rpmdb scriptlets are the signed ones again" 'chroot $W/atk /usr/bin/rpm --dbpath /var/lib/rpm -q --scripts rpm | grep -qv PWNED && ! chroot $W/atk /usr/bin/rpm --dbpath /var/lib/rpm -q --scripts --triggers --filetriggers rpm systemd-ft | grep -q PWNED'
apply_in "$W/atk" "$H" "$W/plan" --apply > "$W/apply2.out" 2>&1
check "second apply is a no-op" 'grep -q "changed=0 " $W/apply2.out && grep -q "finalize: not needed" $W/apply2.out'
S2=$(collect "$W/atk" "$H" 2>/dev/null); plan "$S2" "$W/plan2"
check "re-plan after repair has 0 actions" 'grep -q "(0 actions, 0 packages" $W/plan2.out'
check "gpgcheck=0 repo file restored; report-only unpinned key still listed" '! grep -q "gpgcheck=0" $W/plan2/report.txt && grep -q "not pinned" $W/plan2/report.txt && grep -q "^gpgcheck=1" $W/atk/etc/yum.repos.d/rocky.repo'
cp -a "$W/pristine" "$W/rb"; collect "$W/rb" "$H" >/dev/null 2>&1
apply_in "$W/rb" "$H" "$W/plan" --apply > "$W/rb-apply.out" 2>&1
RBW=$(grep -o '/var/lib/pmtrust/run-[0-9TZ]*' "$W/rb-apply.out" | head -1)
unshare -u -m sh -c "hostname $H; chroot $W/rb /root/pmtrust/plan/bin/busybox sh /root/pmtrust/plan/apply.sh --rollback $RBW" > "$W/rollback.out" 2>&1
diff -r --no-dereference -q "$W/rb" "$W/pristine" 2>/dev/null | grep -vE "(/root/pmtrust|/var/lib/pmtrust|rb/root: pmtrust|rb/var/lib: pmtrust|/proc|/dev)" > "$W/rollback.diff"
check "rollback restores the attacked tree exactly" '[ ! -s $W/rollback.diff ]'
check "rollback fires no planted attack" '[ -z "$(markers $W/rb)" ]'
echo "== $H (synthetic rpm): $PASS passed, $FAIL failed (details in $W)"
[ "$FAIL" = 0 ]
