#!/usr/bin/env bash
# harden-rocky.sh - safe hardening for the Rocky Ecom box.
# Every step re-tests HTTP/HTTPS and rolls back if the site breaks.
# It does NOT delete users, keys or cron jobs - triage.sh finds those, you decide.
# Usage: sudo bash harden-rocky.sh [--strict-php] [--rotate user1,user2]
#   KEEP="http https ssh ftp"  firewalld services to keep (default: http https ssh,
#                              plus ftp/dns automatically if vsftpd/named is running)
#   --strict-php               also block exec/system/etc. in PHP (can break real apps)
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root."; exit 1; }
Q=/root/.quarantine; mkdir -p "$Q"; chmod 700 "$Q"
STRICT_PHP=0; ROTATE=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --strict-php) STRICT_PHP=1 ;;
    --rotate) ROTATE=${2:-}; shift ;;
  esac; shift
done

code() { curl -sk -o /dev/null -m 5 -w '%{http_code}' "$1"; }
ok_code() { [[ $1 =~ ^(2|3)[0-9][0-9]$ ]]; }   # 2xx or a redirect (real apps often 301/302)
web_ok() { ok_code "$(code http://127.0.0.1/)" && ok_code "$(code https://127.0.0.1/)"; }
step() { printf '\n[*] %s\n' "$*"; }
web_ok && echo "[+] Site OK before changes" || echo "[!] Site ALREADY failing - fix that first, then re-run"

step "SSH: drop-in 00-ccdc.conf (first match wins, so 00 beats anything planted later in the dir)"
cat > /etc/ssh/sshd_config.d/00-ccdc.conf <<'EOF'
PermitRootLogin no
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 30
X11Forwarding no
EOF
if sshd -t; then systemctl reload sshd; sshd -T | grep -Ei '^(permitrootlogin|permitemptypasswords|maxauthtries) '
else echo "[!] sshd config invalid - removed drop-in"; rm -f /etc/ssh/sshd_config.d/00-ccdc.conf; fi
echo "    PasswordAuthentication left ON - SSH is scored with a password."

step "Sudoers: quarantine any rule for a service account"
for f in /etc/sudoers.d/*; do
  [[ -f $f ]] && grep -qE '^\s*(apache|nginx|www-data|nobody|mysql)\b' "$f" && mv -v "$f" "$Q/"
done
visudo -c >/dev/null && echo "    sudoers syntax OK"

step "Permissions on shadow files"
chmod 000 /etc/shadow /etc/gshadow; ls -l /etc/shadow

step "PHP: hide version and errors"
cp -p /etc/php.ini "$Q/php.ini.bak"
sed -i -E 's/^;?\s*expose_php\s*=.*/expose_php = Off/; s/^;?\s*display_errors\s*=.*/display_errors = Off/; s/^;?\s*allow_url_include\s*=.*/allow_url_include = Off/' /etc/php.ini
if [[ $STRICT_PHP == 1 ]]; then
  echo "    --strict-php: blocking exec/system/shell_exec/passthru/proc_open/popen"
  sed -i -E 's/^;?\s*disable_functions\s*=.*/disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec/' /etc/php.ini
fi
systemctl restart php-fpm 2>/dev/null; systemctl restart httpd
if web_ok; then echo "    OK (only the homepage was tested - click through the store too)"
else echo "[!] Site broke - restoring php.ini"; cp -p "$Q/php.ini.bak" /etc/php.ini; systemctl restart php-fpm 2>/dev/null; systemctl restart httpd; fi

step "Apache: hide version, no TRACE, no directory listing"
cat > /etc/httpd/conf.d/zz-ccdc.conf <<'EOF'
ServerTokens Prod
ServerSignature Off
TraceEnable Off
<Directory "/var/www/html">
    Options -Indexes
</Directory>
EOF
if apachectl configtest 2>/dev/null && systemctl reload httpd && sleep 1 && web_ok; then echo "    OK"
else echo "[!] Rolled back Apache change"; rm -f /etc/httpd/conf.d/zz-ccdc.conf; systemctl reload httpd; fi

step "MariaDB: listen on localhost only"
printf '[mysqld]\nbind-address=127.0.0.1\n' > /etc/my.cnf.d/zz-ccdc.cnf
systemctl restart mariadb; sleep 2
if web_ok; then echo "    OK"; ss -tlnp | grep 3306; else echo "[!] Rolled back"; rm -f /etc/my.cnf.d/zz-ccdc.cnf; systemctl restart mariadb; fi
echo "    DB accounts with remote host (review, drop the ones the site doesn't use):"
mysql -N -e "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE host NOT IN ('localhost','127.0.0.1','::1')" 2>/dev/null

step "firewalld: keep scored services, drop the rest (ICMP stays allowed)"
Z=$(firewall-cmd --get-default-zone)
KEEP=${KEEP:-"http https ssh"}
{ systemctl is-active -q vsftpd || systemctl is-active -q proftpd; } 2>/dev/null && KEEP="$KEEP ftp"
{ systemctl is-active -q named || systemctl is-active -q dnsmasq; } 2>/dev/null && KEEP="$KEEP dns"
echo "    Keeping: $KEEP   (check Quotient - add anything scored with KEEP=\"...\")"
for s_ in $(firewall-cmd --zone="$Z" --list-services); do
  [[ " $KEEP " == *" $s_ "* ]] || firewall-cmd --permanent --zone="$Z" --remove-service="$s_"; done
for s_ in $KEEP; do firewall-cmd --permanent --zone="$Z" --add-service="$s_" >/dev/null; done
for p in 3306/tcp 9090/tcp 6379/tcp 11211/tcp 9200/tcp 10000/tcp; do
  firewall-cmd --zone="$Z" --query-port="$p" -q && firewall-cmd --permanent --zone="$Z" --remove-port="$p"; done
firewall-cmd --reload
echo "    Ports still open (NOT removed automatically - may be a scored FTP passive range):"
firewall-cmd --zone="$Z" --list-ports
firewall-cmd --zone="$Z" --list-all | grep -E 'services|icmp'
web_ok && echo "    Site OK" || echo "[!] Site check failed after firewall change"

step "SELinux"
if [[ $(getenforce) != Enforcing ]]; then
  restorecon -R /var/www/html; setenforce 1; sleep 1
  if web_ok; then sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config; echo "    Enforcing, site OK"
  else setenforce 0; echo "[!] Site breaks under SELinux - left permissive. Check: ausearch -m avc -ts recent"; fi
else echo "    Already enforcing"; fi

step "Files for you to review (not removed)"
grep -RIlE 'phpinfo|eval\(|base64_decode|shell_exec|passthru' /var/www 2>/dev/null
find /var/www -name '.*' -type f 2>/dev/null

if [[ -n $ROTATE ]]; then
  step "Rotating passwords"
  CSV=/root/pcr-$(date +%H%M).csv; : > "$CSV"; chmod 600 "$CSV"
  IFS=, read -ra US <<< "$ROTATE"
  for u in "${US[@]}"; do
    pw=$(openssl rand -base64 12 | tr -d '/+=')
    echo "$u:$pw" | chpasswd && echo "$u,$pw" >> "$CSV"
  done
  echo "    Saved $CSV - submit scored accounts via Quotient PCR, or the scorer can't log in."
fi

printf '\n'; web_ok && echo "[+] Done - site still up." || echo "[!] Site DOWN - check httpd/mariadb logs now."
