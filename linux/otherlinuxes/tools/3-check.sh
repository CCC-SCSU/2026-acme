#!/bin/sh
# 3-check.sh -- READ ONLY. Is this box's shell, tmux and package manager trustworthy?
#   sudo sh 3-check.sh
# Changes nothing. Run this BEFORE you trust anything the box's own tools tell you.
# NOTE: if the box is deeply compromised the package manager can lie to you. A clean result here
# is reassuring, not proof. A dirty result is proof of a problem.
h(){ echo; echo "===== $* ====="; }
have(){ command -v "$1" >/dev/null 2>&1; }
BAD=0
flag(){ echo "  !! $*"; BAD=$((BAD+1)); }

h "WHAT SHELL AND TOOLS ARE HERE"
for t in sh bash tmux screen ps ls netstat ss find grep; do
  p=$(command -v $t 2>/dev/null)
  if [ -n "$p" ]; then printf '  %-8s %-22s %s\n' "$t" "$p" "$(sha256sum "$p" 2>/dev/null | cut -c1-16)"
  else printf '  %-8s (not installed)\n' "$t"; fi
done

h "DO THOSE BINARIES MATCH THEIR PACKAGE?"
echo "  (ignoring docs/man/locale -- those are stripped on minimal images and mean nothing)"
REAL='/(s?bin|lib|lib64|libexec)/'   # paths worth caring about
if have dpkg; then
  for t in bash tmux ls ps find grep; do
    p=$(command -v $t 2>/dev/null) || continue
    [ -n "$p" ] || continue
    pkg=$(dpkg -S "$(readlink -f "$p")" 2>/dev/null | head -1 | cut -d: -f1)
    if [ -z "$pkg" ]; then flag "$p belongs to NO package (hand-placed binary)"; continue; fi
    out=$(dpkg --verify "$pkg" 2>/dev/null | grep -v ' c /' | grep -E "$REAL")
    if [ -n "$out" ]; then
      echo "$out" | grep -qF "$(readlink -f "$p")" && flag "THE $t BINARY ITSELF IS ALTERED ($p)" \
        || flag "$pkg has altered executables/libraries:"
      echo "$out" | sed 's/^/      /'
    else echo "  ok  $t ($pkg)"; fi
  done
elif have rpm; then
  for t in bash tmux ls ps find grep; do
    p=$(command -v $t 2>/dev/null); [ -n "$p" ] || continue
    pkg=$(rpm -qf "$p" 2>/dev/null)
    case "$pkg" in *"not owned"*|"") flag "$p belongs to NO package (hand-placed binary)"; continue;; esac
    out=$(rpm -V "$pkg" 2>/dev/null | grep -v ' c /' | grep -E "$REAL")
    if [ -n "$out" ]; then
      echo "$out" | grep -qF "$(readlink -f "$p")" && flag "THE $t BINARY ITSELF IS ALTERED ($p)" \
        || flag "$pkg has altered executables/libraries:"
      echo "$out" | sed 's/^/      /'
    else echo "  ok  $t ($pkg)"; fi
  done
elif have pacman; then
  for t in bash tmux ls ps find grep; do
    p=$(command -v $t 2>/dev/null); [ -n "$p" ] || continue
    pkg=$(pacman -Qoq "$p" 2>/dev/null)
    if [ -z "$pkg" ]; then flag "$p belongs to NO package (hand-placed binary)"; continue; fi
    out=$(pacman -Qkk "$pkg" 2>&1 | grep -iE 'altered|missing|mismatch' | grep -E "$REAL")
    if [ -n "$out" ]; then flag "$pkg has altered files:"; echo "$out" | sed 's/^/      /'
    else echo "  ok  $t ($pkg)"; fi
  done
else
  echo "  no dpkg/rpm/pacman -- cannot verify binaries against packages here"
fi

h "PACKAGE MANAGER CONFIG -- SIGNATURE CHECKING"
if have apt-get; then
  grep -rsi 'AllowUnauthenticated\|Insecure' /etc/apt/apt.conf /etc/apt/apt.conf.d/ 2>/dev/null \
    | grep -vi 'false\|"0"' | while read -r l; do echo "  !! $l"; done
  grep -rsi 'AllowUnauthenticated.*true\|Insecure.*true' /etc/apt/apt.conf.d/ >/dev/null 2>&1 && BAD=$((BAD+1))
  echo "  (anything printed above means apt was told to skip signature checks)"
fi
if have dnf || have yum; then
  grep -rs 'gpgcheck *= *0' /etc/yum.conf /etc/dnf/dnf.conf /etc/yum.repos.d/ 2>/dev/null \
    | while read -r l; do echo "  !! signature check DISABLED: $l"; done
fi
if have pacman; then
  grep -s 'SigLevel' /etc/pacman.conf | grep -i 'never' | while read -r l; do echo "  !! $l"; done
fi

h "PACKAGE MANAGER HOOKS (these run commands as root on every install)"
if have apt-get; then
  STOCK='00trustcdrom|01autoremove|01-vendor|10periodic|15update-stamp|20packagekit|20archive|20auto-upgrades|20snapd|50appstream|50command-not-found|60icons|70debconf|90cloud-init|99needrestart|99update-notifier|docker-clean'
  grep -rsl 'Pre-Invoke\|Post-Invoke\|Pre-Install-Pkgs' /etc/apt/apt.conf.d/ 2>/dev/null | while read -r f; do
    b=$(basename "$f")
    if grep -qsE '(Pre-Invoke|Post-Invoke|Pre-Install-Pkgs).*(curl|wget|nc |ncat|/dev/tcp|base64|eval|/tmp/)' "$f"; then
      echo "  !! $f runs a NETWORK/EXEC command -- backdoor pattern:"; grep -s 'Invoke\|Pkgs' "$f" | sed 's/^/        /'
    elif echo "$b" | grep -qE "^($STOCK)"; then
      echo "  ok  $b (standard hook)"
    else
      echo "  ?? $f is non-standard:"; grep -s 'Invoke\|Pkgs' "$f" | sed 's/^/        /'
    fi; done
  echo "  (a Pre-Invoke running curl/wget/nc/base64 is a backdoor, not a feature)"
fi
if have pacman; then
  for d in /etc/pacman.d/hooks /usr/share/libalpm/hooks; do
    [ -d "$d" ] || continue
    ls -la "$d" 2>/dev/null | sed 's/^/  /'
  done
fi
[ -d /etc/dnf/plugins ] && { echo "  --- dnf plugins"; ls -la /etc/dnf/plugins 2>/dev/null | sed 's/^/  /'; }

h "WHERE ARE PACKAGES COMING FROM? (an unknown host here is very bad)"
if have apt-get; then grep -rhs '^deb ' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | sed 's/^/  /'
  ls /etc/apt/sources.list.d/ 2>/dev/null | sed 's/^/  file: /'; fi
if have dnf || have yum; then grep -rhs 'baseurl\|metalink\|mirrorlist' /etc/yum.repos.d/ 2>/dev/null | sed 's/^/  /'; fi
if have pacman; then grep -s '^Server' /etc/pacman.d/mirrorlist 2>/dev/null | head -10 | sed 's/^/  /'
  grep -s '^\[' /etc/pacman.conf | sed 's/^/  repo: /'; fi

h "CONFIG FILES CHANGED IN THE LAST 4 HOURS"
find /etc/apt /etc/yum.repos.d /etc/yum.conf /etc/dnf /etc/pacman.conf /etc/pacman.d \
     -type f -mmin -240 2>/dev/null | sed 's/^/  !! /'

h "PATH HIJACKING (a fake binary earlier in PATH beats the real one)"
echo "  PATH=$PATH"
case ":$PATH:" in
  *:.:*|*::*) flag "PATH contains the current directory -- anything you cd into can hijack commands";;
esac
for d in $(echo "$PATH" | tr ':' ' '); do
  case "$d" in /tmp*|/var/tmp*|/dev/shm*|/home/*) flag "PATH includes a writable/odd directory: $d";; esac
done
for t in bash tmux ls ps; do
  n=$(command -v -a $t 2>/dev/null | wc -l)
  [ "${n:-0}" -gt 1 ] && { echo "  !! more than one '$t' in PATH:"; command -v -a $t | sed 's/^/      /'; }
done

h "SHELL STARTUP FILES (run every time you log in)"
for f in /etc/profile /etc/bash.bashrc /etc/bashrc /root/.bashrc /root/.profile /root/.bash_profile; do
  [ -f "$f" ] || continue
  out=$(grep -nEs 'curl|wget|nc |ncat|/dev/tcp|base64 -d|eval |PATH=' "$f")
  [ -n "$out" ] && { echo "  --- $f"; echo "$out" | sed 's/^/      /'; }
done

h "TMUX CONFIG (tmux can be told to log or mirror your session)"
for f in /etc/tmux.conf /root/.tmux.conf /home/*/.tmux.conf; do
  [ -f "$f" ] 2>/dev/null || continue
  echo "  --- $f"; grep -nEs 'run-shell|pipe-pane|if-shell|source' "$f" | sed 's/^/      /'
done
echo "  (pipe-pane or run-shell in a tmux config can copy everything you type to a file or a socket)"

echo
echo "================================================================"
if [ "$BAD" = 0 ]; then
  echo " No hard failures found. Still read the sections above yourself."
else
  echo " $BAD problem(s) flagged with !! -- look at those first."
fi
echo " Reminder: a compromised box's own tools can lie. If anything above"
echo " looks wrong, switch to your own trusted binaries (see tools/README.txt)."
echo "================================================================"
