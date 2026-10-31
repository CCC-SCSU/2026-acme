#!/bin/sh
# 4-fixrepo.sh -- clean up a tampered package manager. Asks before every change.
#   sudo sh 4-fixrepo.sh
# Run 3-check.sh FIRST to see what is wrong. This only offers to fix what it finds.
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
ask(){ printf '%s [y/N] ' "$1"; read a; [ "$a" = y ] || [ "$a" = Y ]; }
have(){ command -v "$1" >/dev/null 2>&1; }
STAMP=$(date +%m%d-%H%M)
echo "Anything removed is MOVED ASIDE, not deleted (.disabled-$STAMP), so you can put it back."
echo

if have apt-get; then
  echo "=== APT ==="
  # These ship with Debian/Ubuntu and legitimately use Invoke hooks. Do not offer to remove them.
  STOCK='00trustcdrom|01autoremove|01-vendor|10periodic|15update-stamp|20packagekit|20archive|20auto-upgrades|20snapd|50appstream|50command-not-found|60icons|70debconf|90cloud-init|99needrestart|99update-notifier|docker-clean|01-vendor-ubuntu'
  for f in /etc/apt/apt.conf.d/*; do
    [ -f "$f" ] || continue
    b=$(basename "$f")
    # a hook matters when it pulls from the network or decodes/evals something
    if grep -qsE '(Pre-Invoke|Post-Invoke|Pre-Install-Pkgs).*(curl|wget|nc |ncat|/dev/tcp|base64|eval|/tmp/|python -c|perl -e)' "$f"; then
      echo "--- $f runs a NETWORK/EXEC command on every apt operation. This is a backdoor pattern:"
      grep -sE 'Invoke|Pkgs' "$f" | sed 's/^/      /'
      ask "  Disable this file?" && mv "$f" "$f.disabled-$STAMP" && echo "  moved aside."
    elif grep -qsE 'Pre-Invoke|Post-Invoke|Pre-Install-Pkgs' "$f"; then
      if echo "$b" | grep -qE "^($STOCK)"; then
        echo "    ok  $b (standard Debian/Ubuntu hook, leave it alone)"
      else
        echo "--- $f is a NON-STANDARD file with an apt hook:"
        grep -sE 'Invoke|Pkgs' "$f" | sed 's/^/      /'
        echo "    (if your team did not add this, it should not be here)"
        ask "  Disable this file?" && mv "$f" "$f.disabled-$STAMP" && echo "  moved aside."
      fi
    fi
    if grep -qsiE 'AllowUnauthenticated *"?true|Insecure *"?true' "$f"; then
      echo "--- $f turns OFF signature checking"
      ask "  Disable this file?" && mv "$f" "$f.disabled-$STAMP" && echo "  moved aside."
    fi
  done
  echo "--- package sources:"; grep -rhs '^deb ' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | sed 's/^/      /'
  for f in /etc/apt/sources.list.d/*; do
    [ -f "$f" ] || continue
    echo "--- extra source file: $f"; grep -s '^deb' "$f" | sed 's/^/      /'
    ask "  Disable it? (say no if your team added it)" && mv "$f" "$f.disabled-$STAMP"
  done
  echo "--- trusted keys (an extra key lets an attacker sign their own packages):"
  ls -la /etc/apt/trusted.gpg.d/ 2>/dev/null | sed 's/^/      /'
fi

if have dnf || have yum; then
  echo "=== DNF / YUM ==="
  grep -rsl 'gpgcheck *= *0' /etc/yum.repos.d/ /etc/yum.conf /etc/dnf/dnf.conf 2>/dev/null | while read -r f; do
    echo "--- $f has signature checking DISABLED"
    if ask "  Turn gpgcheck back on in $f?"; then
      cp "$f" "$f.bak-$STAMP"; sed -i 's/^gpgcheck *= *0/gpgcheck=1/' "$f"; echo "  fixed (backup: $f.bak-$STAMP)"
    fi
  done
  echo "--- repositories:"; grep -rhs '^\[\|baseurl\|metalink' /etc/yum.repos.d/ 2>/dev/null | sed 's/^/      /'
fi

if have pacman; then
  echo "=== PACMAN ==="
  if grep -qs 'SigLevel.*Never' /etc/pacman.conf; then
    echo "--- /etc/pacman.conf has SigLevel Never (signatures not checked)"
    grep -n 'SigLevel' /etc/pacman.conf | sed 's/^/      /'
    if ask "  Change 'Never' to 'Required DatabaseOptional'?"; then
      cp /etc/pacman.conf /etc/pacman.conf.bak-$STAMP
      sed -i 's/SigLevel *= *Never/SigLevel = Required DatabaseOptional/' /etc/pacman.conf
      echo "  fixed (backup: /etc/pacman.conf.bak-$STAMP)"
    fi
  fi
  for d in /etc/pacman.d/hooks /usr/share/libalpm/hooks; do
    [ -d "$d" ] || continue
    for f in "$d"/*.hook; do
      [ -f "$f" ] || continue
      if grep -qsE 'curl|wget|nc |ncat|/dev/tcp|base64' "$f"; then
        echo "--- $f runs a network command on every package operation:"; sed 's/^/      /' "$f"
        ask "  Disable this hook?" && mv "$f" "$f.disabled-$STAMP"
      fi
    done
  done
  echo "--- mirrors:"; grep -s '^Server' /etc/pacman.d/mirrorlist 2>/dev/null | head -5 | sed 's/^/      /'
fi

echo
echo "Done. Re-run 3-check.sh to confirm."
echo "If a repo or key was replaced and you cannot tell what the original was, do NOT install"
echo "anything from it. File a ticket and work without the package manager instead."
