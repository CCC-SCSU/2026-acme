# Ecommerce VM: Rocky Linux 9

|                              |                                                                                        |
| ---------------------------- | -------------------------------------------------------------------------------------- |
| **Internal IP**        | 172.20.240.10                                                                          |
| **Public IP**          | 172.25.20+team#.10                                                                     |
| **Login**              | sysadmin / Changeme1!                                                                  |
| **Scored (pack)**      | HTTP, HTTPS (page content must match the expected file), most likely SSH and ping      |
| **Check Quotient for** | Any other check listed for this box (FTP and DNS are scored somewhere, box not stated) |
| **Must stay up**       | `httpd` (Apache), `php-fpm` (runs the PHP app), `mariadb` (store data), `sshd` |

## Ground rules

1. Test the website after **every** change: `curl -s http://localhost/ | head`
2. **Lock** suspicious accounts, never delete them.
3. Never rename users, hostnames or IPs.
4. No source-IP allowlisting on public services. Keep ICMP (ping) working.
5. If you change a password the scorer uses, submit it through **Quotient PCR** (CSV: `username,password`).
6. Changing the DB password means changing it in **both** MariaDB and the app's config file.
7. Write a log line for every change: **time, what, why**. Incident reports come from this log.
8. Move suspicious files to `/root/.bk/` instead of deleting them. They are evidence.

---

## 1. Lock the door

**1.1 Change your own password**

```
passwd
```

**1.2 Change root's password**

```
sudo passwd root
```

**1.3 See who else is logged in**

```
w
who
last -n 20
```

- **Look for:** sessions from IPs that aren't your team, logins at times you weren't on.
- **Fix:** kick a session by its terminal from the `w` output:

```
sudo pkill -KILL -t pts/1
```

**1.4 Log it**

- `00:01 changed sysadmin + root passwords`
- If sysadmin is a scored account, submit the new password through PCR now.

---

## 2. Back up

**2.1 Make the backup**

```
sudo mkdir -p /root/.bk && sudo chmod 700 /root/.bk
sudo tar czpf /root/.bk/etc.tgz /etc
sudo tar czpf /root/.bk/www.tgz /var/www
sudo tar czpf /root/.bk/root.tgz --exclude=/root/.bk /root
sudo sh -c 'mysqldump --all-databases --single-transaction > /root/.bk/all-db.sql'
sudo ls -lh /root/.bk
```

- **Check:** every file is bigger than 0 bytes, and the dump has tables:

```
sudo grep -c "CREATE TABLE" /root/.bk/all-db.sql
```

**2.2 Copy it off the box** (the red team may delete local backups)

```
sudo scp -r /root/.bk sysadmin@172.20.240.15:~/rocky-bk
```

- `172.20.240.15` is the destination machine. Use any teammate box you trust.

**2.3 Restore one file**

```
sudo tar xzpf /root/.bk/etc.tgz -C / etc/httpd/conf/httpd.conf
```

**2.4 Restore the database**

```
sudo sh -c 'mysql < /root/.bk/all-db.sql'
```

---

## 3. Find services and ports (4:00–6:00)

**3.1 What's listening**

```
sudo ss -tulpn
```

- **Expected:** 22 (sshd), 80 and 443 (httpd), 3306 on `127.0.0.1` only (mariadb), maybe 323 (chronyd) and 9090 (cockpit).
- **Suspicious:** anything else on `0.0.0.0` or `*` (like 4444 or 1337); `nc`, `python`, `perl` or `bash` listening; 3306 on `0.0.0.0`.

**3.2 What's installed, enabled and running**

```
systemctl list-unit-files --state=enabled --type=service
systemctl list-units --type=service --state=running
rpm -qa | grep -iE "ftp|bind|dnsmasq|postfix|splunk|redis|memcache|elastic|opensearch|tomcat|node|docker|podman|samba|nfs|webmin|cockpit|phpmyadmin"
sudo docker ps -a 2>/dev/null; sudo podman ps -a 2>/dev/null
```

- Compare against the **services table** below and against Quotient.

**3.3 Are the scored services running?**

```
systemctl is-active httpd php-fpm mariadb sshd firewalld
```

- **Expected:** all say `active`.

**3.4 What web app is this?**

```
sudo httpd -S
ls /etc/httpd/conf.d/
ls -la /var/www/html
curl -s http://localhost/ | head -30
```

- `httpd -S` shows the virtual hosts and the DocumentRoot (where the site lives). More than one vhost or port means a second site to check.
- `conf.d/` can hide phpMyAdmin, aliases or reverse proxies to other backends.
- **App clues:** `wp-config.php` = WordPress, `admin/config.php` = OpenCart, `app/config/parameters.php` = PrestaShop, `app/etc/env.php` = Magento.

**3.5 Find the app's database credentials**

```
sudo grep -rniE "db_pass|db_password|database_password|'password'|DB_USER" /var/www 2>/dev/null | head -20
```

- Write down the **config file path** and the **DB username**. You need both for any DB password change.

**3.6 Save the "before" homepage**

```
sudo sh -c 'curl -s http://localhost/ > /root/.bk/home-before.html'
sudo sh -c 'curl -sk https://localhost/ > /root/.bk/home-before-https.html'
```

### Possible services on this box

| Service                       | Port                      | Why it might be here               | Check                                  | Scored? / action                       |
| ----------------------------- | ------------------------- | ---------------------------------- | -------------------------------------- | -------------------------------------- |
| Apache (`httpd`)            | 80, 443                   | Serves the store                   | `systemctl status httpd`             | **Scored.** Keep up              |
| PHP-FPM (`php-fpm`)         | socket                    | Runs the store's PHP code          | `systemctl status php-fpm`           | Needed by the site. Keep up            |
| MariaDB (`mariadb`)         | 3306                      | Store data                         | `ss -tlnp \| grep 3306`               | Needed. Localhost only                 |
| SSH (`sshd`)                | 22                        | Remote admin                       | `systemctl status sshd`              | Likely scored. Harden, keep up         |
| FTP (`vsftpd`, `proftpd`) | 21 + passive range        | Uploading product images and files | `systemctl status vsftpd`            | Scored if on Quotient. Harden, keep up |
| DNS (`named`, `dnsmasq`)  | 53                        | Some scenarios put DNS on Linux    | `systemctl status named dnsmasq`     | Scored if on Quotient                  |
| Postfix (local)               | 25                        | Store sends order emails           | `systemctl status postfix`           | Keep, listen on localhost only         |
| Splunk Universal Forwarder    | 8089 local, sends to 9997 | Ships logs to Splunk               | `ls /opt/splunkforwarder`            | Keep. Don't break log shipping         |
| Cockpit                       | 9090                      | Default on Rocky 9, web admin      | `systemctl status cockpit.socket`    | Not scored. Disable                    |
| phpMyAdmin / Adminer          | inside Apache             | Web DB admin                       | `ls /usr/share/phpMyAdmin; httpd -S` | Big target. Remove or restrict         |
| Redis / Memcached             | 6379 / 11211              | Store caching                      | `systemctl status redis memcached`   | Localhost only                         |
| Elasticsearch / OpenSearch    | 9200                      | Store search (Magento)             | `ss -tlnp \| grep 9200`               | Localhost only                         |
| Tomcat / Node.js              | 8080, 3000                | Second app or API                  | `ss -tlnp`                           | Investigate                            |
| Docker / Podman               | anything                  | Services hidden in containers      | `docker ps -a; podman ps -a`         | Investigate                            |
| Samba / NFS                   | 445 / 2049                | File shares                        | `systemctl status smb nfs-server`    | Investigate                            |
| Webmin                        | 10000                     | Web admin, weak passwords          | `ss -tlnp \| grep 10000`              | Not scored. Disable                    |
| chronyd                       | 323/udp                   | Time sync                          | `systemctl status chronyd`           | Normal. Leave                          |

**Decision rule for unknown services:**

1. On Quotient = scored. Secure it, keep it running and reachable.
2. Not on Quotient, but the business plausibly needs it = keep it, restrict it (localhost only, close the port).
3. Not on Quotient, no business reason = `sudo systemctl disable --now NAME`, log why.
4. Not sure = block it in the firewall instead of stopping it. Easier to undo.

---

## 4. Find all accounts

**4.1 Extra root accounts** (only `root` should have UID 0)

```
awk -F: '$3==0' /etc/passwd
```

- **Bad:** any other name, like `sysbackup`.
- **Fix:** lock it. Don't delete it, because a UID-0 account shares root's files.

```
sudo usermod -L -s /sbin/nologin sysbackup
```

**4.2 Accounts that can log in**

```
grep -vE "nologin|false|sync|shutdown|halt" /etc/passwd
```

- **Expected:** root, sysadmin, real staff accounts.
- **Suspicious:** service accounts (apache, mysql, nobody) with `/bin/bash`, unfamiliar names, names that imitate system ones.
- **Fix** a service account's shell:

```
sudo usermod -s /sbin/nologin apache
```

**4.3 Empty passwords**

```
sudo awk -F: '$2==""{print $1}' /etc/shadow
```

- **Expected:** prints nothing.
- **Fix:** for any name it prints:

```
sudo passwd -l USER
```

**4.4 Who has admin rights**

```
getent group wheel
sudo grep -vE "^\s*(#|$)" /etc/sudoers
sudo ls -la /etc/sudoers.d/
sudo sh -c 'cat /etc/sudoers.d/*'
```

- **Bad:** unknown users in wheel; `NOPASSWD: ALL` for anyone, especially `apache`.
- **Fix:**

```
sudo gpasswd -d USER wheel
sudo mv /etc/sudoers.d/BADFILE /root/.bk/
sudo visudo -c
```

- `visudo -c` must say `parsed OK`. A broken sudoers file can lock you out of sudo.

**4.5 SSH keys** (a key lets someone in without a password)

```
sudo find / -xdev -name "authorized_keys*" 2>/dev/null
sudo cat /root/.ssh/authorized_keys
sudo sh -c 'cat /home/*/.ssh/authorized_keys'
sudo lsattr /root/.ssh/authorized_keys
```

- **Bad:** any key you didn't put there, comments like `redteam@kali`. An `i` in `lsattr` means the file is immutable (can't be edited).
- **Fix:**

```
sudo chattr -i /root/.ssh/authorized_keys
sudo vi /root/.ssh/authorized_keys
```

- Delete the bad line, save.

**4.6 Lock a bad account and kick it out**

```
sudo usermod -L -s /sbin/nologin -e 1 USER
sudo pkill -KILL -u USER
```

- Log the name, time and reason.

---

## 5. Find persistence

**5.1 Cron jobs**

```
sudo cat /etc/crontab
sudo ls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/
sudo sh -c 'cat /etc/cron.d/*'
sudo ls /var/spool/cron/
for u in $(cut -d: -f1 /etc/passwd); do sudo crontab -l -u $u 2>/dev/null | grep -v "^#" | sed "s/^/$u: /"; done
```

- **Bad:** jobs running hidden files (names starting with `.`) or files in `/tmp`, `/var/tmp`, `/dev/shm`, `/usr/local/bin`; anything with `curl`, `wget`, `nc`, `bash -i`, `/dev/tcp`; `@reboot` entries; any cron job for `apache`.
- **Fix:**

```
sudo mv /etc/cron.d/BADFILE /root/.bk/
sudo crontab -r -u apache
```

**5.2 Systemd services and timers**

```
ls -la /etc/systemd/system/*.service /etc/systemd/system/*.timer 2>/dev/null
systemctl list-timers --all
systemctl list-units --type=service --state=running
```

- `/etc/systemd/system/` normally holds mostly symlinks. A real file with a vague name ("network-helper", "dbus-update") is suspicious.
- **Inspect:** look at `ExecStart`:

```
systemctl cat NAME.service
```

- **Fix:**

```
sudo systemctl disable --now NAME.service
sudo mv /etc/systemd/system/NAME.service /root/.bk/
sudo systemctl daemon-reload
```

**5.3 Odd files and login hooks**

```
ls -la /usr/local/bin /usr/local/sbin
ls -la /tmp /var/tmp /dev/shm
ls -la /etc/profile.d/
cat /etc/ld.so.preload 2>/dev/null
```

- **Bad:** hidden or executable files in temp folders, unfamiliar scripts in `profile.d`. Any content in `/etc/ld.so.preload` is a classic rootkit trick.

**5.4 SUID files** (programs that run as root)

```
sudo find / -xdev -perm -4000 -type f 2>/dev/null
```

- **Bad:** `find`, `vim`, `python`, `bash`, or anything in `/tmp` or `/var/tmp`.
- **Fix:**

```
sudo chmod u-s /usr/bin/find
sudo mv /var/tmp/.bash /root/.bk/
```

**5.5 Suspicious processes**

```
ps -eo pid,ppid,user,etime,cmd --sort=user | grep -v "\[" | less
```

- **Bad:** `nc`, `ncat`, `socat`, `python -c`, `bash -i`, `sh` running as apache, processes started from `/tmp`.
- **Fix:** kill it, then find what started it (cron or a service), or it comes back:

```
sudo kill -9 PID
```

---

## 6. Harden SSH and the firewall

**6.1 SSH drop-in file** (in `sshd_config.d/` the first value wins, so `00-` beats anything planted later)

```
sudo ls -la /etc/ssh/sshd_config.d/
sudo vi /etc/ssh/sshd_config.d/00-ccdc.conf
```

- **Contents:**

```
PermitRootLogin no
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 30
X11Forwarding no
```

- **Apply and check:**

```
sudo sshd -t && sudo systemctl reload sshd
sudo sshd -T | grep -Ei "permitrootlogin|permitemptypasswords|maxauthtries|passwordauthentication"
```

- `sshd -t` must print nothing. Any output is a syntax error. Don't reload until it's clean.
- Leave `PasswordAuthentication yes`. The scorer probably logs in with a password.
- Move other planted files in `sshd_config.d/` (like `01-legacy.conf`) to `/root/.bk/`.
- Keep your current session open. Test a new login from a second window before closing it.

**6.2 Firewall (firewalld)**

```
sudo firewall-cmd --get-default-zone
sudo firewall-cmd --list-all
```

- **Expected:** services `http https ssh` (plus any scored service such as `ftp` or `dns`), nothing in `ports:`.
- **Fix:** remove extras:

```
sudo firewall-cmd --permanent --remove-service=cockpit
sudo firewall-cmd --permanent --remove-port=3306/tcp
sudo firewall-cmd --permanent --add-service={http,https,ssh}
sudo firewall-cmd --reload
sudo firewall-cmd --list-all
curl -s http://localhost/ | head
```

- Never add rules that only allow certain source IPs. ICMP stays allowed (firewalld allows it by default).

---

## 7. Web and database

**7.1 SELinux**

```
getenforce
```

- If `Permissive` or `Disabled`, someone may have turned it off. Re-enable carefully:

```
sudo restorecon -Rv /var/www/html
sudo setenforce 1
curl -s http://localhost/ | head
```

- **Site works:** make it permanent: set `SELINUX=enforcing` in `/etc/selinux/config`.
- **Site breaks:** undo at once, then check why:

```
sudo setenforce 0
sudo ausearch -m avc -ts recent
```

**7.2 Database listens only locally**

```
sudo ss -tlnp | grep 3306
```

- **Expected:** `127.0.0.1:3306`.
- **Fix** if it shows `0.0.0.0:3306`:

```
sudo grep -r bind-address /etc/my.cnf /etc/my.cnf.d/
```

- Set `bind-address=127.0.0.1` in that file, then:

```
sudo systemctl restart mariadb
curl -s http://localhost/ | head
```

**7.3 Database users**

```
sudo mysql -e "SELECT user,host FROM mysql.user;"
sudo mysql -e "SHOW GRANTS FOR 'APPUSER'@'localhost';"
```

- **Bad:** users with host `%` (connect from anywhere) that the app doesn't use; the app user with `ALL ON *.*`.
- **Fix:** keep the `@'localhost'` account the app's config uses:

```
sudo mysql -e "DROP USER 'shopuser'@'%';"
```

**7.4 Leftover web files**

```
sudo find /var/www -name "*.php" -newer /etc/hostname -ls
sudo grep -rlE "eval\(|base64_decode|shell_exec|passthru|system\(|phpinfo" /var/www
sudo find /var/www -name ".*" -type f
```

- **Bad:** `info.php` (phpinfo), hidden PHP files, files in `uploads/`, anything recently modified that you didn't touch.
- **Fix:** move them out, keep the evidence:

```
sudo mv FILE /root/.bk/
```

**7.5 PHP settings**

```
grep -E "^(display_errors|expose_php|allow_url_include)" /etc/php.ini
```

- **Want:** `display_errors = Off`, `expose_php = Off`, `allow_url_include = Off`. Edit the file, then:

```
sudo systemctl restart php-fpm httpd
```

---

## 8. Verify

**8.1 The site works and looks the same**

```
systemctl is-active httpd php-fpm mariadb sshd
curl -s http://localhost/ | head
curl -sk https://localhost/ | head
curl -s http://localhost/ > /tmp/home-after.html
sudo diff /root/.bk/home-before.html /tmp/home-after.html && echo SAME
```

**8.2 Check Quotient**

- All checks for this box green? If not, go to **Service_Down_Checklist.md**.

**8.3 Finish the log**

- Every change: time, what, why, evidence (file, user, IP).
- Red-team activity becomes an **incident report** (section 9.8).

---

## 9. After 15 minutes

**9.1 Re-check persistence every 30–45 min** (the red team comes back)

```
awk -F: '$3==0' /etc/passwd
getent group wheel
sudo ls -la /etc/sudoers.d/ /etc/cron.d/ /etc/ssh/sshd_config.d/
sudo find / -xdev -name "authorized_keys*" -newer /root/.bk/etc.tgz 2>/dev/null
sudo find /etc /var/www /usr/local /tmp /var/tmp -xdev -newer /root/.bk/etc.tgz -type f 2>/dev/null | head -50
ls -la /etc/systemd/system/*.service
sudo ss -tulpn
```

- `-newer /root/.bk/etc.tgz` lists everything changed since your backup. Anything you didn't touch is suspicious.

**9.2 Watch logs live** (use a second terminal)

```
sudo tail -f /var/log/secure /var/log/httpd/access_log /var/log/httpd/error_log
```

- **SSH logins and brute force:**

```
sudo grep -E "Accepted|Failed password" /var/log/secure | tail -30
sudo grep "Failed password" /var/log/secure | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head
```

- **Web attacks** (SQL injection, scanners, web shells):

```
sudo grep -iE "union|select|sleep\(|\.\./|cmd=|c=|eval|base64|sqlmap|nikto|wget|curl" /var/log/httpd/access_log | tail -30
sudo awk '{print $1}' /var/log/httpd/access_log | sort | uniq -c | sort -rn | head
```

- **Sudo use:**

```
sudo grep sudo /var/log/secure | tail -20
```

**9.3 Block one malicious IP** (allowed: specific bad IPs, never "allow only")

```
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="BAD.IP" drop'
sudo firewall-cmd --reload
```

- Make sure it's not the scoring engine. If a check goes red right after, remove the rule:

```
sudo firewall-cmd --permanent --remove-rich-rule='rule family="ipv4" source address="BAD.IP" drop'
sudo firewall-cmd --reload
```

**9.4 Patch**

```
sudo dnf check-update
sudo dnf update -y
sudo systemctl restart httpd php-fpm
curl -s http://localhost/ | head
```

- If the site breaks after an update, check `sudo tail /var/log/httpd/error_log` first.

**9.5 Change the DB password** (both places)

```
sudo mysql -e "ALTER USER 'APPUSER'@'localhost' IDENTIFIED BY 'NewPass';"
sudo vi /var/www/html/CONFIGFILE
curl -s http://localhost/ | head
```

- Use the config path from step 3.5. Test right away. If the site errors, the two passwords don't match.

**9.6 Fix app vulnerabilities**

- Change the default admin password in the app's own admin panel.
- SQL injection: replace string-built queries with prepared statements (see `fixes/product.php`).
- Remove installer folders the app left behind (`install/`, `setup/`).
- Check upload folders can't run PHP:

```
sudo find /var/www -type d -name "upload*"
```

- Block PHP in that folder. Rocky runs PHP through php-fpm, so `php_admin_flag` does nothing there; use a deny rule instead:

```
sudo vi /etc/httpd/conf.d/zz-uploads.conf
```

- **Contents** (replace the path with the upload folder you found):

```
<Directory "/var/www/html/uploads">
    <FilesMatch "\.(php|phtml|phar)$">
        Require all denied
    </FilesMatch>
</Directory>
```

```
sudo apachectl configtest && sudo systemctl reload httpd
curl -s http://localhost/ | head
```

**9.7 Hide version info**

```
sudo vi /etc/httpd/conf.d/zz-ccdc.conf
```

- **Contents:**

```
ServerTokens Prod
ServerSignature Off
TraceEnable Off
```

```
sudo apachectl configtest && sudo systemctl reload httpd
```

**9.8 Write incident reports**

- What happened, source and destination IPs, timeline, what was affected, remediation.
- Pull evidence from section 9.2 and your change log.

**9.9 Refresh the backup** after big fixes

```
sudo tar czpf /root/.bk/etc-2.tgz /etc
sudo sh -c 'mysqldump --all-databases --single-transaction > /root/.bk/all-db-2.sql'
```
