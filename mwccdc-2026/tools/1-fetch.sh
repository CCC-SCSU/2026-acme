#!/bin/sh
# 1-fetch.sh -- RUN THIS ON YOUR OWN MACHINE, BEFORE COMPETITION DAY. Not on a competition box.
#   sh 1-fetch.sh
# Downloads the binaries listed in urls.txt into ./bin/ and writes SHA256SUMS.
# Then you ship the whole ccdc folder to the boxes and 2-install.sh verifies the hashes there.
#
# WHY THIS WAY: you cannot safely download a trusted tool using a box you do not trust. Its curl,
# its DNS and its CA store could all be lying. Fetch on a clean machine, carry the hashes in, verify
# on arrival. If a file does not match its hash, you know before you run it as root.
case "$1" in -h|--help|help)
  awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0;; esac
cd "$(dirname "$0")" || exit 1
mkdir -p bin
[ -f urls.txt ] || { echo "urls.txt missing"; exit 1; }
if command -v curl >/dev/null 2>&1; then GET="curl -fL --connect-timeout 20 -o"
elif command -v wget >/dev/null 2>&1; then GET="wget -T 20 -O"
else echo "need curl or wget"; exit 1; fi

echo "Fetching into $(pwd)/bin"
n=0; fail=0
while read -r name url; do
  case "$name" in ''|\#*) continue;; esac
  [ -n "$url" ] || continue
  printf '  %-10s ' "$name"
  if $GET "bin/$name.part" "$url" >/dev/null 2>&1 && [ -s "bin/$name.part" ]; then
    mv "bin/$name.part" "bin/$name"; chmod +x "bin/$name"
    printf 'ok  %s  %s bytes\n' "$(sha256sum "bin/$name" | cut -c1-16)" "$(wc -c < "bin/$name")"
    n=$((n+1))
  else
    rm -f "bin/$name.part"; echo "FAILED (check the URL in urls.txt)"; fail=$((fail+1))
  fi
done < urls.txt

[ "$n" -gt 0 ] || { echo "nothing downloaded"; exit 1; }
( cd bin && sha256sum * > ../SHA256SUMS 2>/dev/null )
echo
echo "Got $n file(s), $fail failed. Hashes written to SHA256SUMS:"
cat SHA256SUMS
echo
echo "  NOW DO THIS, it is the whole point:"
echo "  1. Open each project's release page and compare the hash above to the one THEY publish."
echo "     If they do not match, delete the file. Do not take the hash from the download itself."
echo "  2. Sanity check each binary on your own machine:   ./bin/bash --version"
echo "  3. Re-pack the kit so the binaries travel with it:"
echo "       cd ../..  &&  tar czf mwccdc-2026.tgz ccdc"
