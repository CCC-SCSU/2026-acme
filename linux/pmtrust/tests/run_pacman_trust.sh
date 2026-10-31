#!/bin/bash
# Trust-chain negative tests for the pacman backend (synthetic web of trust).
set -uo pipefail
SNAP=$(ls -t /srv/t/porky/root/pmtrust/out/*.tar.gz | head -1)
A=/srv/t/arch-mirror; K=/srv/t/arch-keys; B=/srv/t/arch
PASS=0; FAIL=0
ok()  { echo "PASS  $*"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $*"; FAIL=$((FAIL+1)); }
PINS=$(sed 's/^/--expect-fpr /' $B/masters | tr '\n' ' ')
run() { local name=$1 want=$2 pat=$3; shift 3
    rm -rf /srv/t/pt-out; python3 /home/claude/pmtrust/pmtrust.py plan --agent /srv/t/agent --snapshot "$SNAP" --out /srv/t/pt-out \
        --pacman-archive "file://$A" --keyring "$K" "$@" > /srv/t/pt.log 2>&1; local rc=$?
    if [ $rc = $want ] && grep -qE "$pat" /srv/t/pt.log; then ok "$name"; else bad "$name (rc=$rc)"; grep FATAL /srv/t/pt.log | head -2; fi; }
fresh() { rm -rf "$A" "$K"; cp -a $B/archive "$A"; cp -a $B/keyrings "$K"; }
P=packages/l/libarchive/libarchive-3.7.7-1-x86_64.pkg.tar.zst
fresh; run "baseline verifies"                                   0 "0 critical, 0 warnings" $PINS
fresh; run "no pins and no --trust-keyring is refused"           1 "pin the Arch master signing keys"
fresh; run "pins that are not the masters are refused"            1 "not master keys listed in archlinux-trusted" --expect-fpr $(cat $B/packager)
fresh; GNUPGHOME=$B/gnupg gpg --batch --yes --default-key $(cat $B/rogue) --detach-sign -o "$A/$P.sig" "$A/$P" 2>/dev/null
run "package signed by a key with one master certification is refused" 1 "not certified by enough pinned master keys" $PINS
fresh; python3 - "$A/$P" <<'EOF'
import sys; p = sys.argv[1]; b = bytearray(open(p, "rb").read()); b[len(b) // 2] ^= 1; open(p, "wb").write(bytes(b))
EOF
run "same-size tampered package is refused"                       1 "BADSIG|signature is bad" $PINS
fresh; echo "$(cat $B/packager)" > "$K/archlinux-revoked"
run "package by a revoked packager key is refused"                1 "unknown key|signature is bad|no valid" $PINS
fresh; cp "$A/packages/g/gnupg/gnupg-2.4.7-1-x86_64.pkg.tar.zst" "$A/$P"; cp "$A/packages/g/gnupg/gnupg-2.4.7-1-x86_64.pkg.tar.zst.sig" "$A/$P.sig"
run "validly signed but substituted package is refused (.PKGINFO)" 1 "signed .PKGINFO says" $PINS
fresh; rm "$A/$P.sig"; run "missing signature is refused"           1 "refusing an unsigned package" $PINS
echo "== pacman trust chain: $PASS passed, $FAIL failed"
