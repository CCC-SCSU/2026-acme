#!/usr/bin/env bash
# SSH + sysctl hardening (+ optional cron/at lockdown). Backs up and validates sshd config before reloading.
# Env: PERMIT_ROOT=no|yes (default no)
#      ALLOW_USERS="you teammate"   SSH AllowUsers whitelist. DANGEROUS WHERE SSH IS SCORED:
#                                   it is deny-by-default, so any account you leave out -- including
#                                   the scoring engine's -- fails to log in and the check fails.
#                                   The guided run never sets this. Only pass it if you have the full
#                                   list of scoring usernames, and test a scored check right after.
#      PASSAUTH=yes|no              only changes PasswordAuthentication if you set it (default: leave as is)
#      NO_FWD=yes                   also disable TCP forwarding (breaks ssh -J / tunnels THROUGH this box)
#      SSH_PORT=NNNN                optional port change. Open it in the firewall FIRST. Fedora/SELinux needs semanage;
#                                   skipped on Ubuntu using ssh.socket.
#      LOCK_CRON=yes CRON_USERS="svc"   only root + these users may use crontab/at
case "$1" in -h|--help|help)
  awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0;; esac
export PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
# Run bare from a terminal with no settings given? Say what will happen and make them confirm.
if [ -z "$PERMIT_ROOT$ALLOW_USERS$PASSAUTH$SSH_PORT$LOCK_CRON" ] && [ -t 0 ]; then
  echo "harden.sh will CHANGE this box:"
  echo "  - /etc/ssh/sshd_config : root login off, MaxAuthTries 5, no X11, 30s grace"
  echo "  - reload sshd (config is tested first; restored automatically if it fails)"
  echo "  - /etc/sysctl.d/99-ccdc.conf : 6 network settings"
  echo "  - tighten permissions on /etc/shadow /etc/gshadow"
  echo "No SSH allow-list was given, so none will be set. See: bash harden.sh --help"
  printf 'Continue? [y/N] '; read _a
  case "$_a" in y|Y) ;; *) echo "nothing changed."; exit 0;; esac
fi
cfg=${SSHD_CONFIG:-/etc/ssh/sshd_config}; [ -f "$cfg" ] || { echo "no $cfg"; exit 1; }
bak=$cfg.bak.$(date +%s); cp -a "$cfg" "$bak"
restore(){ cp -a "$bak" "$cfg"; echo "$1 -- restored $bak"; exit 1; }
if [ -n "$SSH_PORT" ] && systemctl is-active --quiet ssh.socket 2>/dev/null; then
  echo "ssh.socket is active (Ubuntu 22.10+): Port in sshd_config is ignored, skipping SSH_PORT."; SSH_PORT=""
fi
keys="PermitRootLogin PermitEmptyPasswords MaxAuthTries X11Forwarding LoginGraceTime"
[ -n "$PASSAUTH" ]      && keys="$keys PasswordAuthentication"
[ "$NO_FWD" = yes ]     && keys="$keys AllowTcpForwarding"
if [ -n "$ALLOW_USERS" ]; then
  echo "WARNING: you asked to set AllowUsers to: $ALLOW_USERS"
  echo "         AllowUsers is DENY-BY-DEFAULT. Every account NOT in that list -- including"
  echo "         any scoring account you have not named -- will be refused by sshd, and if"
  echo "         SSH is scored, that check fails."
  if [ -t 0 ]; then
    printf 'Continue? [y/N] '; read _a
    case "$_a" in y|Y) ;; *) echo "aborted, nothing changed"; rm -f "$bak"; exit 0;; esac
  elif [ "$I_KNOW_SSH_ISNT_SCORED" = 1 ]; then
    echo "         (I_KNOW_SSH_ISNT_SCORED=1 given, proceeding)"
  else
    echo "REFUSING: cannot ask for confirmation (no terminal) and this can break a scored"
    echo "          service. Re-run interactively, or if you are certain SSH is not scored:"
    echo "              sudo I_KNOW_SSH_ISNT_SCORED=1 ALLOW_USERS=\"...\" bash harden.sh"
    rm -f "$bak"; exit 1
  fi
  keys="$keys AllowUsers"
fi
[ -n "$SSH_PORT" ]      && keys="$keys Port"
for k in $keys; do sed -i "s/^\s*$k\b/#&/" "$cfg"; done
{
  echo "PermitRootLogin ${PERMIT_ROOT:-no}"
  echo "PermitEmptyPasswords no"
  echo "MaxAuthTries 5"
  echo "LoginGraceTime 30"
  echo "X11Forwarding no"
  [ -n "$PASSAUTH" ]    && echo "PasswordAuthentication $PASSAUTH"
  [ "$NO_FWD" = yes ]   && echo "AllowTcpForwarding no"
  [ -n "$ALLOW_USERS" ] && echo "AllowUsers $ALLOW_USERS"
  [ -n "$SSH_PORT" ]    && echo "Port $SSH_PORT"
  cat "$cfg"
} > /tmp/sshd_new && install -m 600 /tmp/sshd_new "$cfg" && rm -f /tmp/sshd_new
command -v restorecon >/dev/null && restorecon "$cfg" 2>/dev/null
sshd -t || restore "sshd config invalid"
if [ -n "$SSH_PORT" ] && command -v getenforce >/dev/null && [ "$(getenforce)" = Enforcing ]; then
  command -v semanage >/dev/null || restore "SELinux enforcing but semanage missing (install policycoreutils-python-utils first)"
  semanage port -a -t ssh_port_t -p tcp "$SSH_PORT" 2>/dev/null || semanage port -m -t ssh_port_t -p tcp "$SSH_PORT"
fi
act=reload; [ -n "$SSH_PORT" ] && act=restart
unit=""
for u in sshd ssh; do systemctl cat "$u.service" >/dev/null 2>&1 && { unit=$u; break; }; done
if [ -n "$unit" ]; then
  if systemctl $act "$unit"; then echo "$unit ${act}ed."
  else echo "systemctl $act $unit FAILED -- restoring config"; restore "ssh $act failed"; fi
else echo "could not find an ssh/sshd unit; config written but NOT reloaded. Reload it yourself."; fi
echo "Keep this session open and test a NEW login before closing it."

if [ "$LOCK_CRON" = yes ]; then
  wrote=""
  command -v crontab >/dev/null && { { echo root; for u in $CRON_USERS; do echo "$u"; done; } > /etc/cron.allow; chmod 600 /etc/cron.allow; wrote="cron"; }
  command -v at      >/dev/null && { { echo root; for u in $CRON_USERS; do echo "$u"; done; } > /etc/at.allow;   chmod 600 /etc/at.allow;   wrote="$wrote at"; }
  if [ -n "$wrote" ]; then echo "limited to root $CRON_USERS:$wrote"
  else echo "no crontab/at installed (normal on Arch -- it uses systemd timers); nothing to lock."
       echo "Check timers instead:  systemctl list-timers --all"; fi
fi
sd=${SYSCTL_DIR:-/etc/sysctl.d}; mkdir -p "$sd"
cat > "$sd/99-ccdc.conf" <<EOT
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.icmp_echo_ignore_broadcasts=1
EOT
command -v restorecon >/dev/null && restorecon "$sd/99-ccdc.conf" 2>/dev/null
sysctl -p "$sd/99-ccdc.conf" >/dev/null && echo "sysctl applied (only the 6 network settings in $sd/99-ccdc.conf)"
chmod o-rwx /etc/shadow /etc/gshadow 2>/dev/null; chmod go-w /etc/passwd /etc/group /etc/shadow 2>/dev/null
