#!/usr/bin/env bash
# Apache recon + hardening for the e-commerce / webmail boxes (apache2 on Ubuntu, httpd on Fedora/RHEL).
# Usage: [DOCROOT=/var/www/html] web-harden.sh          report + back up docroot (changes nothing else)
#        [DOCROOT=...] web-harden.sh apply              also add hardening config (validated, auto-removed if invalid)
# Does NOT change DB passwords or file ownership: either can take the site down. See notes at the end of the report.
case "$1" in -h|--help|help)
  awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0;; esac
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
if command -v apache2ctl >/dev/null; then SVC=apache2; CTL="apache2ctl -t"; CONF=/etc/apache2/conf-available/zz-ccdc.conf
elif command -v httpd >/dev/null;    then SVC=httpd;    CTL="httpd -t";      CONF=/etc/httpd/conf.d/zz-ccdc.conf
else echo "no apache found"; exit 1; fi
ROOT=${DOCROOT:-/var/www/html}; sec(){ echo; echo "===== $* ====="; }
[ -d "$ROOT" ] || { echo "docroot $ROOT not found -- set DOCROOT=<path>"; exit 1; }
bk=/opt/html.BAK.$(date +%Y%m%d-%H%M%S)
mb=$(du -sm "$ROOT" 2>/dev/null | cut -f1); free=$(df -Pm /opt | awk 'NR==2{print $4}')
if [ "${mb:-0}" -gt $(( ${free:-0} / 2 )) ]; then echo "SKIPPING docroot backup (${mb} MB vs ${free} MB free on /opt)"
else cp -a "$ROOT" "$bk" && echo "docroot backed up to $bk (copy it off-box too)"; fi

sec "Possible webshells / backdoors"
grep -rIl --exclude-dir=.git -E '(eval|assert|system|passthru|shell_exec|exec|popen|proc_open)\s*\(\s*(\$_(GET|POST|REQUEST|COOKIE|SERVER)|base64_decode|gzinflate|str_rot13)' "$ROOT" 2>/dev/null
sec "PHP files in upload/cache/tmp/image dirs (usually shouldn't exist)"
find "$ROOT" -xdev -type f -name '*.php*' \( -ipath '*upload*' -o -ipath '*cache*' -o -ipath '*tmp*' -o -ipath '*image*' -o -ipath '*media*' \) 2>/dev/null | head -50
sec "World-writable files/dirs"; find "$ROOT" -xdev \( -type f -o -type d \) -perm -002 2>/dev/null | head -50
sec "Modified in last 24h"; find "$ROOT" -xdev -type f -mtime -1 2>/dev/null | head -50
sec "Hidden files / odd names"; find "$ROOT" -xdev -name '.*' -not -name '.htaccess' -not -name '.' 2>/dev/null | head -30
sec ".htaccess files (check for rewrites/auto_prepend)"; find "$ROOT" -xdev -name .htaccess -exec sh -c 'echo "--- $1"; cat "$1"' _ {} \; 2>/dev/null
sec "Files that hold DB credentials (update THESE if you change the DB password)"
grep -rIlE 'DB_PASSWORD|db_pass|mysqli_connect|mysql_connect|new PDO|dbpassword' "$ROOT" /etc/php* 2>/dev/null | head -20
sec "Apache modules of interest"; ($SVC -M 2>/dev/null || apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null) | grep -Ei 'cgi|status|info|userdir|dav|proxy|autoindex' 

if [ "$1" = apply ]; then
  cat > "$CONF" <<EOT
ServerTokens Prod
ServerSignature Off
TraceEnable Off
<IfModule mod_headers.c>
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-XSS-Protection "1; mode=block"
</IfModule>
<Directory $ROOT>
  Options -Indexes
</Directory>
EOT
  command -v restorecon >/dev/null && restorecon "$CONF" 2>/dev/null
  [ "$SVC" = apache2 ] && { a2enmod headers >/dev/null 2>&1; a2enconf zz-ccdc >/dev/null 2>&1; }
  undo(){ rm -f "$CONF"; [ "$SVC" = apache2 ] && a2disconf zz-ccdc >/dev/null 2>&1; systemctl reload $SVC >/dev/null 2>&1; }
  if $CTL; then
    if systemctl reload $SVC; then
      sleep 2
      if systemctl is-active --quiet $SVC; then echo "hardening applied; CHECK THE SCORED PAGE NOW"
      else undo; systemctl start $SVC; echo "$SVC stopped after reload -- hardening removed and service restarted"; fi
    else undo; echo "reload failed, hardening removed"; fi
  else undo; echo "config test failed, hardening removed"; fi
fi
cat <<'EOT'

NOTES
- Changing the MySQL/MariaDB password: the web app's config file (listed above) holds the old one, so change both in the same minute
  and re-test the page. Modern syntax:  ALTER USER 'root'@'localhost' IDENTIFIED BY 'newpass'; FLUSH PRIVILEGES;
  (the old UPDATE ... PASSWORD() form fails on MySQL 8). Better: give the app its own limited DB user instead of root.
- Don't chown/chmod the docroot until you've confirmed the site doesn't write to it (uploads, sessions, cache).
- Re-run the webshell grep periodically and after any red-team activity.
EOT
