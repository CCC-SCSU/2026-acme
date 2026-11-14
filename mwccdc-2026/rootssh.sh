#!/usr/bin/env bash
# rootssh.sh -- block root over SSH WITHOUT breaking the scored SSH check.
#
#   sudo bash rootssh.sh check      READ ONLY. Who actually logs in over SSH? Has root ever?
#   sudo bash rootssh.sh disable    block root SSH (shows evidence first, auto-restores on failure)
#   sudo bash rootssh.sh enable     put it back, right now
#   sudo bash rootssh.sh status     current setting
#
# WHY A WHOLE SCRIPT FOR ONE SETTING: SSH is a scored service in this competition and the
# team pack never says which account the engine logs in with. If it uses root, setting
# PermitRootLogin no fails that check every 2-4 minutes for the rest of the event. So this
# reads the auth logs FIRST and shows you who has actually been logging in. Evidence, then action.
#
# RULES NOTE: this is a per-ACCOUNT restriction, not source-IP filtering, so it does not run
# into MWCCDC rule 9 (public services must stay reachable from all source IPs). Blocking root
# while leaving the service open to everyone is ordinary hardening and is fine.
export PATH="/usr/sbin:/sbin:/usr/bin:/bin:$PATH"
case "$1" in -h|--help|help|"")
  awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0;; esac
[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo bash $0 $*"; exit 1; }
CFG=${SSHD_CONFIG:-/etc/ssh/sshd_config}
[ -f "$CFG" ] || { echo "no $CFG on this box"; exit 1; }
ask(){ local a; read -r -p "$1 [y/N] " a || return 1; [ "$a" = y ] || [ "$a" = Y ]; }

ssh_unit(){ for u in ssh sshd; do systemctl cat "$u.service" >/dev/null 2>&1 && { echo "$u"; return 0; }; done; return 1; }
# auth records live in /var/log/auth.log on Debian with rsyslog, else in journald
authlog(){
  if [ -r /var/log/auth.log ]; then cat /var/log/auth.log /var/log/auth.log.1 2>/dev/null
  elif [ -r /var/log/secure ]; then cat /var/log/secure /var/log/secure-* 2>/dev/null
  else journalctl -u ssh -u sshd --no-pager 2>/dev/null; fi
}
current(){ sshd -T 2>/dev/null | awk '/^permitrootlogin/{print $2}'; }

evidence(){
  echo "===== WHO HAS SUCCESSFULLY LOGGED IN OVER SSH ====="
  A=$(authlog)
  if [ -z "$A" ]; then
    echo "  !! Could not read any auth log. Without evidence, do NOT guess."
    echo "     Ask your team whether the scoring engine's SSH check uses root."
    return 1
  fi
  ACC=$(echo "$A" | grep -oE 'Accepted [a-z]+ for [A-Za-z0-9_.-]+' | awk '{print $NF}' | sort | uniq -c | sort -rn)
  if [ -n "$ACC" ]; then echo "$ACC" | sed 's/^/  /'
  else echo "  (no 'Accepted' lines yet -- nothing has logged in over SSH on this boot)"; fi
  echo
  echo "===== HAS ROOT LOGGED IN OVER SSH? ====="
  R=$(echo "$A" | grep -E 'Accepted [a-z]+ for root' | tail -5)
  if [ -n "$R" ]; then
    echo "  *** YES -- root HAS logged in over SSH: ***"
    echo "$R" | sed 's/^/    /'
    echo
    echo "  If any of those are the scoring engine, blocking root WILL fail the SSH check."
    echo "  Identify the source IPs above before you proceed."
    return 2
  fi
  echo "  No successful root SSH logins found. Blocking root looks safe."
  echo
  echo "===== FAILED ROOT ATTEMPTS (this is red team or a bot) ====="
  F=$(echo "$A" | grep -cE 'Failed password for root|Failed password for invalid user root' 2>/dev/null)
  echo "  $F failed root login attempts recorded"
  [ "${F:-0}" -gt 0 ] && echo "  <- good reason to block root, and good incident-report material"
  return 0
}

case "$1" in
check)
  echo "Current PermitRootLogin: $(current)"
  echo "Config file: $CFG"
  echo
  evidence
  rc=$?
  echo
  case $rc in
    0) echo "VERDICT: no evidence the scoring engine uses root. 'disable' is low risk.";;
    2) echo "VERDICT: root HAS logged in. Check those IPs before disabling.";;
    *) echo "VERDICT: no evidence available. Confirm with your team first.";;
  esac
  echo "Nothing was changed."
  ;;

status)
  echo "PermitRootLogin (effective): $(current)"
  grep -nE '^[[:space:]]*PermitRootLogin' "$CFG" 2>/dev/null | sed 's/^/  config: /' || echo "  (not set in $CFG; compiled default applies)"
  ls -1t "$CFG".rootssh.bak.* 2>/dev/null | head -3 | sed 's/^/  backup: /'
  ;;

disable)
  echo "Current PermitRootLogin: $(current)"
  echo
  evidence; rc=$?
  echo
  if [ "$rc" = 2 ]; then
    echo "!! root has logged in over SSH on this box. If that was the scoring engine,"
    echo "   this change fails the SSH check every 2-4 minutes until you undo it."
    ask "Block root anyway?" || { echo "nothing changed. Good call -- verify first."; exit 0; }
  elif [ "$rc" != 0 ]; then
    ask "No log evidence either way. Block root anyway?" || { echo "nothing changed."; exit 0; }
  else
    ask "Block root over SSH now?" || { echo "nothing changed."; exit 0; }
  fi

  # make sure a non-root way in exists first, or this is a lockout
  echo
  echo "Accounts that can log in and use sudo:"
  SUDOERS=$(getent group sudo wheel 2>/dev/null | cut -d: -f4 | tr ',' '\n' | grep -v '^$' | sort -u)
  if [ -n "$SUDOERS" ]; then echo "$SUDOERS" | sed 's/^/  /'
  else
    echo "  !! NOBODY is in the sudo or wheel group."
    echo "     Blocking root SSH with no sudo user means you cannot administer this box"
    echo "     remotely at all. Create one first:  sudo bash users.sh newadmin <name>"
    ask "Proceed anyway? (you will still have the NETLAB+ console)" || { echo "nothing changed."; exit 0; }
  fi

  bak="$CFG.rootssh.bak.$(date +%s)"; cp -a "$CFG" "$bak"
  sed -i 's/^[[:space:]]*PermitRootLogin/#&/' "$CFG"
  printf 'PermitRootLogin no\n' | cat - "$CFG" > /tmp/.sshd.new && install -m 600 /tmp/.sshd.new "$CFG" && rm -f /tmp/.sshd.new
  command -v restorecon >/dev/null 2>&1 && restorecon "$CFG" 2>/dev/null

  if ! sshd -t 2>/tmp/.sshderr; then
    echo "sshd rejected the new config -- restoring:"; sed 's/^/    /' /tmp/.sshderr
    cp -a "$bak" "$CFG"; rm -f /tmp/.sshderr; exit 1
  fi
  if ! U=$(ssh_unit); then
    # A config that is changed but not applied is a landmine: the next unrelated sshd
    # restart would disable root SSH with nobody expecting it. Put it back.
    cp -a "$bak" "$CFG"
    echo "Could not find an ssh/sshd systemd unit, so the change was NOT applied and the"
    echo "config has been RESTORED (a pending-but-unapplied change would surprise you later)."
    echo "If you want it anyway, edit $CFG by hand and reload sshd yourself."
    exit 1
  fi
  if systemctl reload "$U" 2>/dev/null || systemctl restart "$U" 2>/dev/null; then
    echo
    echo "  PermitRootLogin is now: $(current)"
    echo "  Your CURRENT session stays alive. Existing logins are unaffected."
    echo
    echo "  TEST THIS NOW, from another window:"
    echo "      ssh <your-sudo-user>@$(hostname -I 2>/dev/null | awk '{print $1}')    should WORK"
    echo "      ssh root@$(hostname -I 2>/dev/null | awk '{print $1}')                should be REFUSED"
    echo
    echo "  WATCH THE SCOREBOARD for the next two check cycles (4-8 minutes)."
    echo "  If the SSH check goes red, undo it immediately:"
    echo "      sudo bash $0 enable"
    echo "  $(date '+%F %T') disabled root SSH login" >> /root/incidents.txt 2>/dev/null
  else
    echo "reload failed -- restoring previous config"; cp -a "$bak" "$CFG"
    systemctl reload "$U" 2>/dev/null; exit 1
  fi
  ;;

enable)
  bak=$(ls -1t "$CFG".rootssh.bak.* 2>/dev/null | head -1)
  if [ -n "$bak" ]; then
    cp -a "$bak" "$CFG"; echo "restored $bak"
  else
    sed -i 's/^[[:space:]]*PermitRootLogin.*/PermitRootLogin yes/' "$CFG"
    grep -qE '^PermitRootLogin' "$CFG" || printf 'PermitRootLogin yes\n' | cat - "$CFG" > /tmp/.s && install -m 600 /tmp/.s "$CFG" && rm -f /tmp/.s
    echo "set PermitRootLogin yes (no backup found)"
  fi
  sshd -t || { echo "config invalid after restore -- fix $CFG by hand"; exit 1; }
  U=$(ssh_unit) && { systemctl reload "$U" 2>/dev/null || systemctl restart "$U" 2>/dev/null; }
  echo "PermitRootLogin is now: $(current)"
  ;;
*) awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1{exit}' "$0";;
esac
exit 0
