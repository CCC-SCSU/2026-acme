#!/usr/bin/env bash
# Package / shell integrity review. Supports Debian/Ubuntu (dpkg), RHEL/Rocky (rpm) and Arch (pacman).
# Usage: pkgcheck.sh verify | shells | extras | unowned
#   verify   files that differ from what their package shipped
#   shells   who owns each shell binary; offers reinstall (asks every time)
#   extras   software added since install / recently installed
#   unowned  executables belonging to no package
# Nothing is changed without a y/N.
# CAVEATS
#  - On a compromised box the package manager itself can lie. Treat results as leads, not proof.
#  - Reinstalling needs a reachable repo. Check that before relying on it.
#  - ARCH: there is no way to reinstall one package at its installed version. `pacman -S` pulls the
#    CURRENT repo version, and a partial upgrade on Arch can break unrelated software. On Arch this
#    script will warn and make you confirm twice.
export PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
ask(){ local a; read -r -p "$1 [y/N] " a || return 1; [ "$a" = y ] || [ "$a" = Y ]; }
if   command -v pacman >/dev/null; then PM=arch
elif command -v dpkg  >/dev/null; then PM=deb
elif command -v rpm   >/dev/null; then PM=rpm
else echo "no dpkg/rpm/pacman found"; exit 1; fi
echo "package manager: $PM"

owner(){ case $PM in
  deb)  dpkg -S "$1" 2>/dev/null | head -1 | cut -d: -f1;;
  rpm)  rpm -qf "$1" 2>/dev/null | head -1;;
  arch) pacman -Qoq "$1" 2>/dev/null | head -1;;
esac; }
reinstall(){ case $PM in
  deb)  apt-get install --reinstall -y "$1";;
  rpm)  dnf reinstall -y "$1" || yum reinstall -y "$1";;
  arch) echo "WARNING: on Arch this installs the CURRENT repo version of '$1', not the version you have."
        echo "         A partial upgrade can break other software. Safer options: restore the file from"
        echo "         /var/cache/pacman/pkg (the package you actually installed), or do a full 'pacman -Syu'."
        ask "   Really run 'pacman -S --noconfirm $1'?" && pacman -S --noconfirm "$1";;
esac; }

case "$1" in
verify)
  case $PM in
    deb)  dpkg --verify 2>/dev/null | grep -vE ' c /';;
    rpm)  rpm -Va 2>/dev/null | grep -vE ' c /';;
    arch) echo "(pacman -Qkk over every package; this takes a few minutes)"
          pacman -Qkk 2>&1 | grep -vE '^[0-9]+ (total files|altered files)|: 0 altered files' | grep -iE 'warning|error|altered|missing|mismatch';;
  esac
  ;;
shells)
  echo "== /etc/shells =="
  pkgs=""
  for s in $(grep -v '^#' /etc/shells 2>/dev/null); do
    [ -x "$s" ] || continue
    p=$(owner "$(readlink -f "$s")")
    echo "$s -> ${p:-UNOWNED (suspicious)}  $(sha256sum "$s" | cut -c1-16)"
    [ -n "$p" ] && pkgs="$pkgs $p"
  done
  echo "== shells assigned to users that are NOT in /etc/shells =="
  getent passwd | awk -F: '{print $1, $7}' | while read -r u sh; do
    [ -n "$sh" ] && ! grep -qx "$sh" /etc/shells 2>/dev/null && echo "$u $sh"; done
  for p in $(echo $pkgs | tr ' ' '\n' | sort -u); do
    ask "Reinstall package '$p'?" && reinstall "$p"
  done
  ;;
extras)
  case $PM in
  deb)
    if [ -f /var/log/installer/initial-status.gz ]; then
      cur=$(mktemp); ini=$(mktemp); man=$(mktemp)
      dpkg-query -W -f='${Package} ${Status}\n' | awk '$NF=="installed"{print $1}' | sort > "$cur"
      zcat /var/log/installer/initial-status.gz | awk '/^Package:/{p=$2} /^Status: install ok installed/{print p}' | sort > "$ini"
      apt-mark showmanual | sort > "$man"
      echo "== Manually-installed packages not in the original install =="
      comm -13 "$ini" "$cur" | comm -12 - "$man" | while read -r p; do
        echo "$p: $(dpkg-query -W -f='${Description}' "$p" 2>/dev/null | head -1)"
        ask "  remove '$p' (apt-get remove, keeps config)?" && apt-get remove "$p"
      done
      rm -f "$cur" "$ini" "$man"
    else
      echo "No initial-status.gz. Recent installs from the dpkg log:"
      grep -h ' install ' /var/log/dpkg.log* 2>/dev/null | sort | tail -80
    fi;;
  rpm)  echo "== Most recently installed RPMs (review by hand) =="; rpm -qa --last | head -80;;
  arch)
    echo "== Most recent pacman installs (newest last) =="
    grep -hE '\[ALPM\] installed' /var/log/pacman.log* 2>/dev/null | tail -60
    echo
    echo "== Explicitly installed packages NOT part of the base system =="
    base=$(pacman -Qgq base base-devel 2>/dev/null | sort -u)
    pacman -Qeq 2>/dev/null | sort > /tmp/.pe
    comm -23 /tmp/.pe <(echo "$base") | head -60
    rm -f /tmp/.pe
    echo
    echo "== Foreign packages (not from any repo: AUR, or hand-installed) =="
    pacman -Qmq 2>/dev/null || echo "(none)"
    echo
    echo "Review the above by hand. Removing on Arch: pacman -Rns <pkg>  (think first: it may be a dependency)";;
  esac
  ;;
unowned)
  case $PM in
    deb)  dpkg -S /usr/bin/* /usr/sbin/* 2>&1 | grep 'no path found' | sed 's/.*pattern //';;
    rpm)  rpm -qf /usr/bin/* /usr/sbin/* 2>&1 | grep 'not owned' | sed 's/^file //; s/ is not owned.*//';;
    arch) for f in /usr/bin/* /usr/sbin/*; do [ -f "$f" ] || continue
            pacman -Qoq "$f" >/dev/null 2>&1 || echo "$f"; done;;
  esac
  echo "== /usr/local/bin, /usr/local/sbin, /opt =="; ls -la /usr/local/bin /usr/local/sbin /opt 2>/dev/null
  ;;
*) awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1{exit}' "$0";;
esac
exit 0
