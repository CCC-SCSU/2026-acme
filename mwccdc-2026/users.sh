#!/usr/bin/env bash
# Usage:
#   users.sh audit                        list risky accounts, keys, sudo
#   SKIP="scoreuser1 scoreuser2" [PWLEN=14] users.sh rotate
#                                         random password for every login user EXCEPT SKIP (asks y/N first).
#                                         Passwords go to a root-only file, NOT the screen/tmux scrollback.
#   users.sh reveal                       print the creds file once so you can copy BY HAND, then shred it (asks first)
#   users.sh keys                         move every authorized_keys aside (*.bak) -- breaks key-based logins!
#   users.sh newadmin <name>              create a sudo/wheel admin (random pw -> creds file); do this BEFORE locking root
#   users.sh lock <user>                  lock an account (root: password lock only, sudo keeps working)
# NOTE: never rotate accounts the scoring engine logs in with; check the packet.
export PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
usage(){ awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; }
ask(){ [ "$CCDC_YES" = 1 ] && return 0; a=""; read -r -p "$1 [y/N] " a || true; [ "$a" = y ] || [ "$a" = Y ]; }
login_users(){ getent passwd | awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)$/ {print $1}'; }
key_files(){ find / \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /mnt -o -path /media -o -path /snap \) -prune -o -name 'authorized_keys*' -type f -print 2>/dev/null; }
valid_name(){ [[ $1 =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; }
# random password with no look-alike characters (0/O, 1/l/I) so it is easy to copy by hand
newpw(){ tr -dc 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789' </dev/urandom | head -c "${PWLEN:-14}"; }
CREDS=/root/.newcreds
case "$1" in
audit)
  echo "== UID 0 ==";            awk -F: '$3==0{print $1}' /etc/passwd
  echo "== Login shells ==";     getent passwd | awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)$/ {print $1, $3, $6, $7}'
  echo "== Empty passwords ==";  awk -F: '$2==""{print $1}' /etc/shadow
  echo "== sudo/wheel/admin =="; getent group sudo wheel admin
  echo "== NOPASSWD ==";         grep -r NOPASSWD /etc/sudoers /etc/sudoers.d 2>/dev/null
  echo "== authorized_keys =="
  key_files | while read -r f; do ls -l "$f"; cat "$f"; echo; done
  echo "== Recent logins ==";    last -n 20
  ;;
rotate)
  targets=""
  for u in $(login_users); do case " $SKIP " in *" $u "*) echo "skipping $u";; *) targets="$targets $u";; esac; done
  [ -n "$targets" ] || { echo "nothing to rotate"; exit 0; }
  echo "Will rotate:$targets"
  ask "Continue?" || exit 0
  ( umask 077; touch "$CREDS" )
  for u in $targets; do
    pw=$(newpw)
    [ "${#pw}" -ge 8 ] || { echo "password generation failed for $u; skipped (an empty password would be a disaster)"; continue; }
    # record BEFORE changing, so a full disk can never leave you with a changed-but-unrecorded password
    ( umask 077; sed -i "/^$u /d" "$CREDS"; echo "$u $pw" >> "$CREDS" ) || { echo "cannot write $CREDS (disk full?); stopping before changing $u"; break; }
    echo "$u:$pw" | chpasswd || { echo "chpasswd failed for $u; password NOT changed"; sed -i "/^$u /d" "$CREDS"; }
  done
  echo "Done. Run '$0 reveal' when you're ready to write them down by hand."
  ;;
reveal)
  [ -s "$CREDS" ] || { echo "nothing to reveal"; exit 1; }
  ask "Print creds to screen now?" || exit 0
  cat "$CREDS"; echo
  read -r -p "Press Enter once written down (screen clears, file is shredded)..." _ || true
  shred -u "$CREDS"; clear
  ;;
keys)
  key_files | while read -r f; do case "$f" in *.bak*) continue;; esac; mv -v "$f" "$f.bak"; done
  ;;
newadmin)
  valid_name "$2" || { echo "usage: $0 newadmin <name>   (lowercase letters, digits, _ and -)"; exit 1; }
  grp=sudo; getent group sudo >/dev/null || grp=wheel
  getent group "$grp" >/dev/null || { echo "neither a sudo nor a wheel group exists; create the admin by hand"; exit 1; }
  id "$2" >/dev/null 2>&1 || useradd -m -s /bin/bash "$2" || { echo "useradd failed"; exit 1; }
  usermod -aG "$grp" "$2" || { echo "could not add $2 to $grp"; exit 1; }
  pw=$(newpw); [ "${#pw}" -ge 8 ] || { echo "password generation failed"; exit 1; }
  ( umask 077; touch "$CREDS"; sed -i "/^$2 /d" "$CREDS"; echo "$2 $pw" >> "$CREDS" ) || { echo "cannot write $CREDS"; exit 1; }
  echo "$2:$pw" | chpasswd || { echo "chpasswd failed"; exit 1; }
  command -v sudo >/dev/null || echo "WARNING: sudo isn't installed, so $2 can't use it"
  echo "$2 is in '$grp'. Password saved; use '$0 reveal'. Test: su - $2 -c 'sudo -v'"
  ;;
lock)
  [ -n "$2" ] || { usage; exit 1; }
  id "$2" >/dev/null 2>&1 || { echo "no such user: $2"; exit 1; }
  [ "$2" = "${SUDO_USER:-}" ] && { echo "refusing to lock the account you're logged in as ($2)"; exit 1; }
  if [ "$2" = root ]; then
    echo "Locks root's PASSWORD only (sudo still works). Make sure a tested sudo admin exists first."
    ask "Lock root?" && passwd -l root
  else
    uid=$(id -u "$2"); usermod -L -e 1 "$2"
    if [ "$uid" = 0 ]; then
      # pkill -u 0 would kill EVERY root process (sshd, journald, ...), so only kill this account's ttys
      echo "$2 has UID 0: not bulk-killing its processes. Locked; ending its terminal sessions only."
      echo "(Also remove it for good: 'userdel $2' or fix its UID, then check /etc/passwd.)"
      who | awk -v u="$2" '$1==u{print $2}' | while read -r t; do pkill -KILL -t "$t" && echo "ended session on $t"; done
    else pkill -KILL -u "$uid"; fi
    echo "locked $2"
  fi
  ;;
*) usage;;
esac
