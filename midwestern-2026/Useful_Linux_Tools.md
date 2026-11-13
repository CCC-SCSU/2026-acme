
| Tool                                    | What it does                                                                  | Install (Rocky / Ubuntu)                           | When to use it                                                                      |
| --------------------------------------- | ----------------------------------------------------------------------------- | -------------------------------------------------- | ----------------------------------------------------------------------------------- |
| **auditd**                        | Kernel-level logging of who ran what and which files were touched             | Built in on Rocky /`apt install auditd`          | First 30 min: watch`/etc/passwd`,`/etc/shadow`, sudoers, SSH keys, the web root |
| **Lynis**                         | Fast security audit with a list of findings and fixes                         | `dnf install lynis`(EPEL) /`apt install lynis` | Once early (~2–3 min run) to catch things you missed                               |
| **rkhunter**/**chkrootkit** | Scans for known rootkits, backdoors, odd SUID files and hidden files          | EPEL / apt                                         | Once early, then again later                                                        |
| **pspy**                          | Shows every process as it starts, including cron jobs that run for one second | Single binary from its GitHub releases page        | Catching hidden cron or systemd persistence live                                    |
| **fail2ban**                      | Bans IPs after repeated failed logins (SSH, web, mail)                        | EPEL / apt                                         | Only after scored passwords are set and submitted, so it can’t ban the scorer      |
| **ClamAV**                        | Antivirus; finds known web shells and malware                                 | EPEL / apt                                         | Scan`/var/www`,`/tmp`,`/home`                                                 |
| **AIDE**                          | File integrity: snapshots file hashes and reports what changed                | `dnf install aide`/ apt                          | Init after hardening, check every hour                                              |
| **tcpdump**                       | Captures network traffic                                                      | dnf / apt                                          | Seeing exactly what a suspicious process talks to                                   |
| **lsof**                          | Shows which files and network connections a process has open                  | dnf / apt                                          | Investigating a suspicious PID                                                      |
| **ModSecurity + OWASP CRS**       | Web application firewall in front of Apache; blocks SQL injection and similar | `dnf install mod_security mod_security_crs`/ apt | Only if you test it, because it can block legitimate pages and break the HTTP check |

**Quick-start commands for the most useful ones:**

**auditd: watch key files**

```
sudo systemctl enable --now auditd
sudo auditctl -w /etc/passwd -p wa -k users
sudo auditctl -w /etc/shadow -p wa -k users
sudo auditctl -w /etc/sudoers.d/ -p wa -k sudo
sudo auditctl -w /root/.ssh/ -p wa -k sshkeys
sudo auditctl -w /var/www/html/ -p wa -k web
sudo ausearch -k users -i | tail -30       # who changed it, with which command
```

* These rules disappear on reboot. To keep them, put the same lines (without `sudo auditctl`) in `/etc/audit/rules.d/ccdc.rules`.

**Lynis: audit the box**

```
sudo lynis audit system --quick
sudo grep -E "warning|suggestion" /var/log/lynis-report.dat | head -40
```

**rkhunter: rootkit scan**

```
sudo rkhunter --propupd          # record current file hashes (do this on a clean box)
sudo rkhunter --check --sk --rwo # show warnings only
```

**ClamAV: scan for web shells**

```
sudo freshclam                   # update signatures
sudo clamscan -r -i /var/www /tmp /var/tmp /home
```

**fail2ban: protect SSH** (Rocky)

```
sudo dnf install -y fail2ban
sudo tee /etc/fail2ban/jail.d/sshd.local >/dev/null <<'EOF'
[sshd]
enabled = true
maxretry = 5
bantime = 600
EOF
sudo systemctl enable --now fail2ban
sudo fail2ban-client status sshd
```

* Keep the ban time short (10 minutes) so a mistake doesn’t lock out the scorer for long. Unban an IP with `sudo fail2ban-client set sshd unbanip IP`.

**AIDE: detect file changes**

```
sudo aide --init
sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
sudo aide --check                # later: lists added, changed and removed files
```
