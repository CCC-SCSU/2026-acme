#!/bin/bash
# Full attack cycle for the pacman backend on the SYNTHETIC Arch root (skill section 6).
set -uo pipefail
CLEAN=/srv/t/arch-clean; H=${1:-porky}
W=/srv/t/cycle-$H
KEY="--pacman-archive file:///srv/t/arch/archive --keyring /srv/t/arch/keyrings $(sed "s/^/--expect-fpr /" /srv/t/arch/masters | tr "\n" " ")"
. /home/claude/pmtrust/tests/harness.sh
PASS=0; FAIL=0
ok()   { echo "PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "FAIL  $*"; FAIL=$((FAIL+1)); }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
plan() { python3 "$PM" plan --snapshot "$1" --out "$2" --agent "$AGENT" $KEY "${@:3}" > "$2.out" 2>&1; }
rm -rf "$W"; mkdir -p "$W"
cp -a "$CLEAN" "$W/atk"; bash /home/claude/pmtrust/tests/plant_pacman.sh "$W/atk" >/dev/null 2>&1; cp -a "$W/atk" "$W/pristine"
S=$(collect "$W/atk" "$H" 2>/dev/null)
check "collect fires no planted attack" '[ -z "$(markers $W/atk)" ]'
plan "$S" "$W/plan"; rc=$?
check "plan exits 2 (critical findings)" '[ $rc = 2 ]'
R="$W/plan/report.txt"
for pat in "ld.so.preload is active" "/usr/bin/pacman (pacman): content differs" "hooks/zz-evil.hook" \
           "20-systemd-sysusers.hook differs" "SigLevel = Never" "XferCommand" "NoUpgrade" \
           "pacman-mirrorlist-20241119-1/install exists" "trust-model always" "(libarchive): content differs" \
           ".pacman.real is not owned"; do
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
unshare -m sh -c "mount -t proc proc $W/atk/proc; chroot $W/atk /usr/bin/pacman -Qkk" > "$W/Qkk.out" 2>&1
check "pacman -Qkk finds no altered content/perms (mtimes differ: --dbonly does not re-extract)" '! grep -E "(SHA256|Size|Permissions|UID|GID|Symlink) mismatch|missing file" $W/Qkk.out | grep -v -e "backup file" -e " /proc " | grep -q .'
check "local db install script is gone" '! ls $W/atk/var/lib/pacman/local/pacman-mirrorlist-*/install 2>/dev/null'
apply_in "$W/atk" "$H" "$W/plan" --apply > "$W/apply2.out" 2>&1
check "second apply is a no-op" 'grep -q "changed=0 " $W/apply2.out && grep -q "finalize: not needed" $W/apply2.out'
S2=$(collect "$W/atk" "$H" 2>/dev/null); plan "$S2" "$W/plan2"
check "re-plan after repair has 0 actions" 'grep -q "(0 actions, 0 packages" $W/plan2.out'
check "report-only findings still listed (gpg.conf trust-model always)" 'grep -q "trust-model always" $W/plan2/report.txt'
cp -a "$W/pristine" "$W/rb"; collect "$W/rb" "$H" >/dev/null 2>&1
apply_in "$W/rb" "$H" "$W/plan" --apply > "$W/rb-apply.out" 2>&1
RBW=$(grep -o '/var/lib/pmtrust/run-[0-9TZ]*' "$W/rb-apply.out" | head -1)
unshare -u -m sh -c "hostname $H; chroot $W/rb /root/pmtrust/plan/bin/busybox sh /root/pmtrust/plan/apply.sh --rollback $RBW" > "$W/rollback.out" 2>&1
diff -r --no-dereference -q "$W/rb" "$W/pristine" 2>/dev/null | grep -vE "(/root/pmtrust|/var/lib/pmtrust|rb/root: pmtrust|rb/var/lib: pmtrust|/proc|/dev)" > "$W/rollback.diff"
check "rollback restores the attacked tree exactly" '[ ! -s $W/rollback.diff ]'
check "rollback fires no planted attack" '[ -z "$(markers $W/rb)" ]'
echo "== $H (synthetic pacman): $PASS passed, $FAIL failed (details in $W)"
[ "$FAIL" = 0 ]
