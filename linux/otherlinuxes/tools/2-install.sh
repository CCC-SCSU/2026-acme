#!/bin/sh
# 2-install.sh -- RUN THIS ON THE COMPETITION BOX. Needs no network.
#   sudo sh 2-install.sh
# Verifies the hashes recorded by 1-fetch.sh, then installs the binaries to /opt/ccdc-bin.
# It does NOT overwrite any system binary. It puts your copies in a separate directory and you
# put that first in your PATH, so your tools win without breaking anything the services depend on.
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
D=$(cd "$(dirname "$0")" && pwd)
DEST=/opt/ccdc-bin
[ -d "$D/bin" ] || { echo "No $D/bin -- run 1-fetch.sh on your own machine first."; exit 1; }
ls "$D"/bin/* >/dev/null 2>&1 || { echo "$D/bin is empty -- run 1-fetch.sh first."; exit 1; }
[ -f "$D/SHA256SUMS" ] || { echo "No SHA256SUMS -- cannot verify these files. Refusing."; exit 1; }

echo "Verifying hashes..."
if ! ( cd "$D/bin" && sha256sum -c ../SHA256SUMS ); then
  echo
  echo "  HASH MISMATCH. A file changed since you fetched it. DO NOT RUN THESE."
  echo "  Re-fetch on your clean machine and copy them over again."
  exit 1
fi

mkdir -p "$DEST" || exit 1
chmod 755 "$DEST"
for f in "$D"/bin/*; do
  b=$(basename "$f")
  cp "$f" "$DEST/$b" && chmod 755 "$DEST/$b" && echo "  installed $DEST/$b"
done

# busybox provides dozens of tools from one file; link the useful ones
if [ -x "$DEST/busybox" ]; then
  echo "  busybox: creating links for its applets"
  for a in ls ps netstat grep find cat sed awk top kill id du df wc sort head tail vi; do
    "$DEST/busybox" "$a" --help >/dev/null 2>&1 && ln -sf "$DEST/busybox" "$DEST/$a"
  done
fi

# an AppImage needs FUSE, which often is not there; extract it instead
for f in "$DEST"/*.appimage "$DEST"/*appimage*; do
  [ -f "$f" ] 2>/dev/null || continue
  if ! "$f" --version >/dev/null 2>&1; then
    echo "  $f will not run directly (FUSE missing?); extracting it"
    ( cd /tmp && "$f" --appimage-extract >/dev/null 2>&1 ) && \
      find /tmp/squashfs-root -type f -perm -111 -name 'tmux*' -exec cp {} "$DEST/tmux" \; 2>/dev/null && \
      chmod 755 "$DEST/tmux" && echo "  extracted $DEST/tmux"
  fi
done

echo
echo "================================================================"
echo " Installed to $DEST. Nothing on the system was replaced."
echo
echo " Use them in THIS shell:"
echo "     export PATH=$DEST:\$PATH"
echo " Check it worked:"
echo "     command -v bash ls      (should show $DEST/...)"
echo
echo " You must run that export in every new shell. That is deliberate:"
echo " a permanent PATH change is itself a persistence mechanism, and you"
echo " do not want to be the thing that looks like red team."
echo "================================================================"
