#!/bin/bash
# Trust-chain negative tests for the rpm backend (synthetic signed repo).
set -uo pipefail
SNAP=$(ls -t /srv/t/foghorn/root/pmtrust/out/*.tar.gz | head -1)
M=/srv/t/rocky-mirror; FPR=$(cat /srv/t/rocky/fpr)
PASS=0; FAIL=0
ok()  { echo "PASS  $*"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $*"; FAIL=$((FAIL+1)); }
run() { local name=$1 want=$2 pat=$3; shift 3
    rm -rf /srv/t/rt-out; python3 /home/claude/pmtrust/pmtrust.py plan --agent /srv/t/agent --snapshot "$SNAP" --out /srv/t/rt-out \
        --rpm-repo "file://$M" --keyring /srv/t/rocky/key.asc "$@" > /srv/t/rt.log 2>&1; local rc=$?
    if [ $rc = $want ] && grep -qE "$pat" /srv/t/rt.log; then ok "$name"; else bad "$name (rc=$rc)"; tail -2 /srv/t/rt.log; fi; }
fresh() { rm -rf "$M"; cp -a /srv/t/rocky/repo "$M"; }
RL=rpm-libs-4.16.1.3-29.el9.x86_64.rpm
fresh; run "baseline verifies"                                  0 "0 critical, 0 warnings" --expect-fpr $FPR
fresh; run "wrong pinned key is refused"                        1 "no acceptable signature" --expect-fpr 0123456789ABCDEF0123456789ABCDEF01234567
fresh; cp /srv/t/rocky/evil/rpm-4.16.1.3-29.el9.x86_64.rpm "$M/"; createrepo_c -q "$M"
run "same-NEVRA package signed by another key is refused"       1 "no acceptable signature" --expect-fpr $FPR
fresh; python3 - "$M/$RL" <<'EOF'
import sys; p = sys.argv[1]; b = bytearray(open(p, "rb").read()); b[-50] ^= 1; open(p, "wb").write(bytes(b))
EOF
createrepo_c -q "$M"
run "payload byte flip (signature still valid) is refused"      1 "payload: sha256 does not match" --expect-fpr $FPR
fresh; python3 - "$M/$RL" <<'EOF'
import sys, struct; p = sys.argv[1]; b = bytearray(open(p, "rb").read())
il, dl = struct.unpack(">II", b[104:112]); off = 96 + 16 + 16 * il + dl; off += (8 - (off - 96) % 8) % 8
il2, dl2 = struct.unpack(">II", b[off + 8:off + 16]); end = off + 16 + 16 * il2 + dl2
i = b.rindex(b"/usr/lib", off, end) + 2       # inside a file path string in the data store
b[i] = ord("X"); open(p, "wb").write(bytes(b))
EOF
createrepo_c -q "$M"
run "header data byte flip (NEVRA intact, metadata regenerated) is refused" 1 "BADSIG|no acceptable signature" --expect-fpr $FPR
fresh; python3 - "$M" <<'EOF'
import glob, gzip, sys; M = sys.argv[1]; p = glob.glob(f"{M}/repodata/*primary.xml*")[0]
import subprocess; data = open(p, "rb").read()
from importlib import util
EOF
P=$(ls $M/repodata/*primary.xml.* | head -1); printf 'x' >> "$P"
run "tampered primary metadata is refused"                      1 "does not match the signed value|sha256 does not match|exceeds the" --expect-fpr $FPR
fresh; cp "$M/$RL" /tmp/x.rpm; rpmsign --delsign "$M/$RL" >/dev/null 2>&1; createrepo_c -q "$M"
run "unsigned package is refused"                               1 "package is not signed" --expect-fpr $FPR
fresh; gpg --homedir /srv/t/rocky/gnupg --batch --yes --armor --detach-sign -o "$M/repodata/repomd.xml.asc" "$M/repodata/repomd.xml" 2>/dev/null
run "signed repomd.xml is verified when present"                0 "repomd.xml: signature verified" --expect-fpr $FPR
printf ' ' >> "$M/repodata/repomd.xml"
run "repomd.xml edited after signing is refused"                1 "BADSIG|no acceptable signature" --expect-fpr $FPR
fresh; run "--require-signed-metadata refuses unsigned repomd"  1 "not signed and --require-signed-metadata" --expect-fpr $FPR --require-signed-metadata
echo "== rpm trust chain: $PASS passed, $FAIL failed"
