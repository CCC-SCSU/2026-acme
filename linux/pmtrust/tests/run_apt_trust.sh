#!/bin/bash
# Trust-chain negative tests for the apt backend, against a local file:// mirror
# built from REAL signed Ubuntu jammy metadata and packages (skill section 6.5).
# Usage: run_apt_trust.sh SNAPSHOT (a jammy snapshot, e.g. from elmer)
set -uo pipefail
SNAP=$1
M=/srv/t/mirror-jammy
PM=/home/claude/pmtrust/pmtrust.py
GOOD=F6ECB3762474EDA9D21B7022871920D1991BC93C
OLD2012=790BC7277767219C42C86F933B4FE6ACC0B21F32
PASS=0; FAIL=0
ok()  { echo "PASS  $*"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $*"; FAIL=$((FAIL+1)); }
run() {  # run NAME EXPECT_RC GREP_PATTERN [extra args]
    local name=$1 want=$2 pat=$3; shift 3
    rm -rf /srv/t/trust-out
    python3 "$PM" plan --agent /srv/t/agent --snapshot "$SNAP" --out /srv/t/trust-out --repo "file://$M" jammy \
        --keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg "$@" > /srv/t/trust.log 2>&1
    local rc=$?
    if [ "$rc" = "$want" ] && grep -qE "$pat" /srv/t/trust.log; then ok "$name (rc=$rc)"
    else bad "$name (rc=$rc, wanted $want /$pat/)"; tail -3 /srv/t/trust.log; fi
}

build_mirror() {
    rm -rf "$M"; mkdir -p "$M/dists/jammy/main/binary-amd64"
    curl -sS -o "$M/dists/jammy/InRelease" https://archive.ubuntu.com/ubuntu/dists/jammy/InRelease
    curl -sS -o "$M/dists/jammy/main/binary-amd64/Packages.xz" \
        https://archive.ubuntu.com/ubuntu/dists/jammy/main/binary-amd64/Packages.xz
    # pool: every package the elmer plan verified, copied from the hash-addressed cache
    python3 - "$M" <<'EOF'
import lzma, os, shutil, sys
M = sys.argv[1]
txt = lzma.decompress(open(f"{M}/dists/jammy/main/binary-amd64/Packages.xz", "rb").read()).decode()
n = 0
for para in txt.split("\n\n"):
    f = dict(l.split(": ", 1) for l in para.splitlines() if ": " in l and not l.startswith(" "))
    sha = f.get("SHA256", "")
    src = f"/srv/t/cache/{sha[:2]}/{sha}"
    if sha and os.path.exists(src):
        dst = f"{M}/{f['Filename']}"
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy(src, dst); n += 1
print(f"mirror: {n} packages")
EOF
}
build_mirror
cp -a "$M/dists/jammy/InRelease" /srv/t/InRelease.good
cp -a "$M/dists/jammy/main/binary-amd64/Packages.xz" /srv/t/Packages.good
restore() { cp /srv/t/InRelease.good "$M/dists/jammy/InRelease"; cp /srv/t/Packages.good "$M/dists/jammy/main/binary-amd64/Packages.xz"; rm -rf "$M/dists/jammy-security"; }

run "baseline: real signed mirror over file:// verifies"          0 "0 critical, 0 warnings" --expect-fpr $GOOD
run "pin replaced by the wrong key (2012 key only) is refused"     1 "no acceptable signature" --expect-fpr $OLD2012
run "no pin and no --trust-keyring is refused"                     1 "pin the signing keys"
python3 - "$M/dists/jammy/InRelease" <<'EOF'
import sys; p = sys.argv[1]; t = open(p).read(); i = t.index("Date: ") + 12
open(p, "w").write(t[:i] + ("1" if t[i] != "1" else "2") + t[i + 1:])
EOF
run "one-byte edit in the signed text is refused"                  1 "BADSIG|no acceptable signature" --expect-fpr $GOOD
restore; printf '\nSuite: jammy-evil\n' >> "$M/dists/jammy/InRelease"
run "data appended after the signature is refused"                 1 "data after the signature" --expect-fpr $GOOD
restore; mkdir -p "$M/dists/jammy-security"; cp /srv/t/InRelease.good "$M/dists/jammy-security/InRelease"
rm -rf /srv/t/trust-out
python3 "$PM" plan --agent /srv/t/agent --snapshot "$SNAP" --out /srv/t/trust-out --repo "file://$M" jammy --repo "file://$M" jammy-security \
    --keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg --expect-fpr $GOOD > /srv/t/trust.log 2>&1; rc=$?
if [ $rc = 1 ] && grep -q "suite substitution" /srv/t/trust.log; then ok "old suite served under a fresher name is refused"; else bad "suite substitution (rc=$rc)"; fi
restore; python3 - "$M/dists/jammy/main/binary-amd64/Packages.xz" <<'EOF'
import lzma, sys; p = sys.argv[1]; t = lzma.decompress(open(p, "rb").read())
t = t.replace(b"Package: dpkg\n", b"Package: dpkg\nX-Evil: 1\n", 1); open(p, "wb").write(lzma.compress(t))
EOF
run "tampered Packages index is refused"                           1 "does not match the signed|size .* does not match" --expect-fpr $GOOD
restore
DEB=$(ls $M/pool/main/d/dpkg/dpkg_*.deb | head -1); cp "$DEB" /srv/t/deb.good
python3 - "$DEB" <<'EOF'
import sys; p = sys.argv[1]; b = bytearray(open(p, "rb").read()); b[len(b) // 2] ^= 1; open(p, "wb").write(bytes(b))
EOF
run "same-size tampered .deb is refused (hash check)"              1 "sha256 does not match" --expect-fpr $GOOD
cp /srv/t/deb.good "$DEB"; printf 'X' >> "$DEB"
run "larger tampered .deb is refused (size cap)"                   1 "exceeds the .*-byte limit|size .* does not match" --expect-fpr $GOOD
cp /srv/t/deb.good "$DEB"
run "restored mirror verifies again"                               0 "0 critical, 0 warnings" --expect-fpr $GOOD
echo "== apt trust chain: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
