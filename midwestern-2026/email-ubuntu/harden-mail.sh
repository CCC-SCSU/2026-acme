#!/usr/bin/env bash
# harden-mail.sh - safe hardening for the Ubuntu Email box.
# Re-tests SMTP/IMAP/POP3/webmail after each step and rolls back if one breaks.
# Does NOT delete users, keys, cron jobs or forwards - triage.sh finds those, you decide.
# Usage: sudo bash harden-mail.sh [--rotate user1,user2]
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root."; exit 1; }
Q=/root/.quarantine; mkdir -p "$Q"; chmod 700 "$Q"

banner() { timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1; IFS= read -r l <&3; echo \"\$l\"" 2>/dev/null; }
svc_ok() {
  local ok=0
  banner 25  | grep -q '^220' || { echo "    SMTP down"; ok=1; }
  banner 143 | grep -q 'OK'   || { echo "    IMAP down"; ok=1; }
  banner 110 | grep -q '+OK'  || { echo "    POP3 down"; ok=1; }
  [[ $(curl -sk -o /dev/null -m 5 -w '%{http_code}' http://127.0.0.1/roundcube/) == 200 ]] || { echo "    Webmail down"; ok=1; }
  return $ok
}
step() { printf '\n[*] %s\n' "$*"; }
svc_ok && echo "[+] All mail services OK before changes" || echo "[!] Something is ALREADY failing - fix that first"

step "SSH: drop-in 00-ccdc.conf"
cat > /etc/ssh/sshd_config.d/00-ccdc.conf <<'EOF'
PermitRootLogin no
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 30
X11Forwarding no
EOF
if sshd -t; then systemctl reload ssh; sshd -T | grep -Ei '^(permitrootlogin|permitemptypasswords|maxauthtries) '
else echo "[!] invalid - removed"; rm -f /etc/ssh/sshd_config.d/00-ccdc.conf; fi

step "Sudoers: quarantine any rule for a service account"
for f in /etc/sudoers.d/*; do
  [[ -f $f ]] && grep -qE '^\s*(www-data|postfix|dovecot|nobody)\b' "$f" && mv -v "$f" "$Q/"
done
visudo -c >/dev/null && echo "    sudoers syntax OK"

step "Permissions on shadow"
chown root:shadow /etc/shadow /etc/gshadow; chmod 640 /etc/shadow /etc/gshadow; ls -l /etc/shadow

step "Postfix: close relay, no VRFY, no hidden BCC"
cp -p /etc/postfix/main.cf "$Q/main.cf.bak"
for k in always_bcc sender_bcc_maps recipient_bcc_maps; do
  v=$(postconf -nh "$k" 2>/dev/null); [[ -n $v ]] && echo "    REMOVING $k = $v" && postconf -X "$k"
done
postconf -e 'mynetworks = 127.0.0.0/8' \
  'smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination' \
  'disable_vrfy_command = yes' 'smtpd_helo_required = yes' 'smtpd_banner = $myhostname ESMTP'
if postfix check && systemctl reload postfix && sleep 1 && svc_ok; then echo "    OK"
else echo "[!] Rolled back main.cf"; cp -p "$Q/main.cf.bak" /etc/postfix/main.cf; systemctl reload postfix; fi
echo "    Queue (stuck mail to outside domains = exfil or relay abuse):"; mailq | tail -3

step "Forwards to outside domains (review and remove by hand)"
D=$(postconf -h mydomain)
grep -vE '^\s*(#|$)' /etc/aliases | grep '@' | grep -v "@$D" && echo "    ^ edit /etc/aliases, then: newaliases"
find /home /root -maxdepth 2 -name .forward 2>/dev/null | while read -r f; do echo "    $f -> $(cat "$f")"; done

step "Apache: hide version, no TRACE"
cat > /etc/apache2/conf-available/zz-ccdc.conf <<'EOF'
ServerTokens Prod
ServerSignature Off
TraceEnable Off
EOF
a2enconf -q zz-ccdc
if apache2ctl configtest 2>/dev/null && systemctl reload apache2 && sleep 1 && svc_ok; then echo "    OK"
else echo "[!] Rolled back"; a2disconf -q zz-ccdc; systemctl reload apache2; fi
grep -q "enable_installer.*true" /etc/roundcube/config.inc.php 2>/dev/null && \
  echo "\$config['enable_installer'] = false;" >> /etc/roundcube/config.inc.php && echo "    Roundcube installer disabled"

step "ufw: allow mail, web, ssh only (ICMP is allowed by ufw defaults)"
for p in 22 25 587 80 443 110 995 143 993; do ufw allow "$p/tcp" >/dev/null; done
ufw --force enable >/dev/null; ufw status numbered
svc_ok && echo "    OK" || { echo "[!] Service failed after ufw - disabling ufw"; ufw disable; }

echo "    Dovecot plaintext auth left ON - IMAP/POP3 are scored with plain logins."

if [[ ${1:-} == --rotate && -n ${2:-} ]]; then
  step "Rotating passwords"
  CSV=/root/pcr-$(date +%H%M).csv; : > "$CSV"; chmod 600 "$CSV"
  IFS=, read -ra US <<< "$2"
  for u in "${US[@]}"; do
    pw=$(openssl rand -base64 12 | tr -d '/+=')
    echo "$u:$pw" | chpasswd && echo "$u,$pw" >> "$CSV"
  done
  echo "    Saved $CSV - submit mail users via Quotient PCR or SMTP/IMAP/POP checks will fail."
fi

printf '\n'; svc_ok && echo "[+] Done - all mail services up." || echo "[!] Something is DOWN - check /var/log/mail.log"
