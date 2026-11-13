---

## When a service is down

**Work through this order:** is it running → is it listening → does it work locally → firewall → SELinux → network (Palo Alto, router).

**First look**

```
systemctl --failed
sudo ss -tulpn
sudo journalctl -p err -n 30 --no-pager
```

### HTTP / HTTPS down

**Step 1. Running?**

```
systemctl is-active httpd php-fpm mariadb
sudo systemctl status httpd --no-pager -l
```

- **Fix:** `sudo systemctl restart httpd`. If it won't start:

```
sudo apachectl configtest
sudo journalctl -u httpd -n 30 --no-pager
```

- **Common causes:**
  - Config syntax error: restore the file from backup (playbook step 2.3).
  - `Address already in use`: something else took 80/443. `sudo ss -tlnp | grep -E ':80 |:443 '`, stop that process.
  - Missing SSL certificate:

```
sudo openssl req -x509 -nodes -newkey rsa:2048 -days 365 -keyout /etc/pki/tls/private/localhost.key -out /etc/pki/tls/certs/localhost.crt -subj "/CN=ecom"
sudo restorecon -v /etc/pki/tls/private/localhost.key /etc/pki/tls/certs/localhost.crt
sudo systemctl restart httpd
```

**Step 2. Works locally?**

```
curl -sI http://localhost/
curl -skI https://localhost/
```

- **200:** Apache is fine. Go to step 4.
- **500:** PHP or app error: `sudo tail -30 /var/log/httpd/error_log`
- **503:** `php-fpm` is down: `sudo systemctl restart php-fpm`
- **403:** file permissions or SELinux. Go to step 5.
- **"Error establishing a database connection" / DB errors:** go to step 3.

**Step 3. Database?**

```
systemctl is-active mariadb
sudo mysql -e "SHOW DATABASES;"
```

- **Fix:** `sudo systemctl restart mariadb`. If tables are gone:

```
sudo sh -c 'mysql < /root/.bk/all-db.sql'
```

- If you changed the DB password, check the app config matches (playbook step 9.5).

**Step 4. Content changed?** (the scorer compares the page)

```
curl -s http://localhost/ > /tmp/now.html
sudo diff /root/.bk/home-before.html /tmp/now.html
```

- **Fix** a defaced site from backup:

```
sudo tar xzpf /root/.bk/www.tgz -C /
sudo restorecon -R /var/www/html
```

**Step 5. SELinux?**

```
getenforce
sudo ausearch -m avc -ts recent
```

- **Fix** labels: `sudo restorecon -Rv /var/www/html`
- **Test:** `sudo setenforce 0`, retry curl. If that fixed it, the problem is SELinux: fix labels or booleans, then `sudo setenforce 1`.
- **Common boolean** (app connects to a DB or API over the network):

```
sudo setsebool -P httpd_can_network_connect_db on
sudo setsebool -P httpd_can_network_connect on
```

**Step 6. Firewall?**

```
sudo firewall-cmd --list-all
```

- **Fix:**

```
sudo firewall-cmd --permanent --add-service={http,https}
sudo firewall-cmd --reload
```

**Step 7. Reachable from outside?** From a workstation VM:

```
curl -sI http://172.20.240.10/
nmap -p 80,443 172.20.240.10
```

- **Works internally but Quotient is red:** the Palo Alto or router is blocking or NAT is broken. Tell the network teammate.

### SSH down

```
systemctl is-active sshd
sudo sshd -t
sudo ss -tlnp | grep :22
sudo firewall-cmd --list-services
```

- **Fix:**
  - `sshd -t` shows an error: fix or remove the bad drop-in, then `sudo systemctl restart sshd`.
  - Not in firewall: `sudo firewall-cmd --permanent --add-service=ssh && sudo firewall-cmd --reload`.
  - Scorer login fails: did you change that user's password without PCR? Is the user locked (`sudo passwd -S USER`)? Did `MaxAuthTries` or `AllowUsers` block it?

### Ping down

```
sudo firewall-cmd --list-icmp-blocks
sudo firewall-cmd --query-icmp-block-inversion
cat /proc/sys/net/ipv4/icmp_echo_ignore_all
ip -br a
ip route
```

- **Fix:**
  - ICMP blocks listed: `sudo firewall-cmd --permanent --remove-icmp-block=echo-request && sudo firewall-cmd --reload`
  - `icmp_echo_ignore_all` is `1`: `sudo sysctl -w net.ipv4.icmp_echo_ignore_all=0`, then check `/etc/sysctl.d/` for the file that set it.
  - Wrong IP or no default route: the interface was changed. Restore with `nmcli`. Never change the IP yourself.

### FTP down (if FTP is on this box)

```
systemctl is-active vsftpd
sudo ss -tlnp | grep :21
sudo grep -vE "^#|^$" /etc/vsftpd/vsftpd.conf
sudo firewall-cmd --list-services
```

- **Fix:**
  - Not running: `sudo systemctl restart vsftpd`, then `sudo journalctl -u vsftpd -n 20 --no-pager`.
  - Firewall: `sudo firewall-cmd --permanent --add-service=ftp && sudo firewall-cmd --reload`.
  - Login works but listing or transfers fail: passive ports (`pasv_min_port`/`pasv_max_port`) must be open too: `sudo firewall-cmd --permanent --add-port=MIN-MAX/tcp && sudo firewall-cmd --reload`.
  - SELinux blocks home directories: `sudo setsebool -P ftpd_full_access on`.
  - Files the scorer reads are missing: restore from backup.

### DNS down (if DNS is on this box)

```
systemctl is-active named
sudo named-checkconf
sudo ss -tulnp | grep :53
dig @localhost DOMAIN-NAME
sudo firewall-cmd --list-services
```

- **Fix:**
  - Config error: `named-checkconf` shows the file and line. Fix or restore from backup.
  - Zone error: `sudo named-checkzone ZONE /var/named/ZONEFILE`.
  - Firewall: `sudo firewall-cmd --permanent --add-service=dns && sudo firewall-cmd --reload`.
  - Listening on 127.0.0.1 only: check `listen-on` and `allow-query` in `/etc/named.conf`.

### Still stuck

- Restore the last config you changed from `/root/.bk/etc.tgz`, restart the service, test.
- Check what you changed in your log right before the check went red. Undo that first.
- Tell the team captain which check is down, since when, and what you've tried
