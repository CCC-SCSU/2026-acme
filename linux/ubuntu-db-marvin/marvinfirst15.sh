
#!/bin/bash

# ============================================================
# CCDC FIRST15 - UBUNTU DATABASE SERVER
# Target: 192.168.220.199
#
# 1. Host identification
# 2. Accounts and SSH security
# 3. Network reconnaissance
# 4. Database and service discovery
# 5. Firewall inspection
# 6. Persistence detection
# 7. log inspection
# 8. System health
#
# READ-ONLY RECONNAISSANCE
# No account, firewall, or service modifications.
# Database backups are performed manually.
#
# Run: sudo bash first15.sh
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "Please run with sudo: sudo bash first15.sh"
    exit 1
fi

export LC_ALL=C

section() {
    echo
    echo "============================================================"
    echo " $1"
    echo "============================================================"
}

subsection() {
    echo
    echo "----- $1 -----"
}

# ============================================================
# 1. HOST IDENTIFICATION
# ============================================================

section "1. HOST IDENTIFICATION"

hostname
hostnamectl
cat /etc/os-release
uname -a
date -Is
uptime

subsection "Current user and privileges"
whoami
id

subsection "Current login sessions"
who
w

subsection "Recent successful logins"
last -n 10


# ============================================================
# 2. ACCOUNTS AND SSH SECURITY
# ============================================================

section "2. ACCOUNTS AND SSH SECURITY"

subsection "All accounts"
getent passwd

subsection "UID 0 accounts"
awk -F: '$3 == 0 {print $1, $3, $6, $7}' /etc/passwd

subsection "Accounts with login shells"
awk -F: '$7 !~ /(nologin|false)$/ {print $1, $3, $6, $7}' /etc/passwd

subsection "Empty password fields"
awk -F: '$2 == "" {print $1}' /etc/shadow

subsection "Locked password accounts"
awk -F: '$2 ~ /^!/ {print $1}' /etc/shadow

subsection "Duplicate UIDs"
awk -F: '{print $3}' /etc/passwd | sort | uniq -d

subsection "Privileged groups"
getent group sudo
getent group adm
getent group docker

subsection "Recent failed logins"
lastb -n 10 2>/dev/null || echo "Failed login history unavailable"

subsection "Sudo configuration"
visudo -c
ls -la /etc/sudoers.d/

subsection "SSH configuration"
if command -v sshd >/dev/null 2>&1; then
    sshd -T 2>/dev/null |
    grep -Ei 'permitrootlogin|passwordauthentication|pubkeyauthentication|permitemptypasswords|allowusers|allowgroups|authenticationmethods|maxauthtries'
else
    echo "OpenSSH server not installed"
fi

# ============================================================
# 3. NETWORK RECONNAISSANCE
# ============================================================

section "3. NETWORK RECONNAISSANCE"

subsection "Network interfaces"
ip -br addr

subsection "Routing table"
ip route

subsection "Network neighbors"
ip neigh

subsection "Listening TCP and UDP ports"
ss -lntup

subsection "Established connections"
ss -tnp state established

subsection "Unix sockets"
ss -lxnp

# ============================================================
# 4. DATABASE AND SERVICE DISCOVERY
# ============================================================

section "4. DATABASE AND SERVICE DISCOVERY"

subsection "Running services"
systemctl --no-pager --type=service --state=running

subsection "Failed services"
systemctl --no-pager --type=service --state=failed

subsection "All loaded services"
systemctl list-units --all --type=service --no-pager

subsection "Installed service files"
systemctl list-unit-files --type=service --no-pager

subsection "CPU-heavy processes"
ps -eo user,pid,ppid,stat,%cpu,%mem,args --sort=-%cpu | head -20

subsection "Memory-heavy processes"
ps -eo user,pid,ppid,stat,%cpu,%mem,args --sort=-%mem | head -20

subsection "Database-related processes"
ps -eo user,pid,ppid,stat,args |
grep -Ei '[m]ysqld|[m]ariadbd|[p]ostgres|[m]ongod|[r]edis-server|[c]assandra|[o]racle|[c]ouchdb|[e]lasticsearch|[c]lickhouse|[s]qlservr'

subsection "Database-related services"
systemctl list-units --all --type=service --no-pager |
grep -Ei 'mysql|maria|postgres|mongo|redis|cassandra|oracle|couchdb|elastic|clickhouse|mssql' || true

subsection "Installed database packages"
if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W -f='${binary:Package}\t${Version}\n' 2>/dev/null |
    grep -Ei 'mysql|maria|postgres|mongo|redis|mssql|sqlite|cassandra|couchdb|elastic|influx|clickhouse' || true
fi

# ============================================================
# 5. FIREWALL INSPECTION
# ============================================================

section "5. FIREWALL INSPECTION"

subsection "UFW status"
if command -v ufw >/dev/null 2>&1; then
    ufw status verbose
    ufw status numbered
else
    echo "UFW not installed"
fi

subsection "NFTables ruleset"
if command -v nft >/dev/null 2>&1; then
    nft -a list ruleset 2>&1
else
    echo "nftables command unavailable"
fi

subsection "IPTables IPv4"
if command -v iptables >/dev/null 2>&1; then
    iptables -S
    iptables -L -n -v
fi

subsection "IPTables IPv6"
if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -S
    ip6tables -L -n -v
fi

subsection "Firewall service status"
for service in ufw nftables firewalld netfilter-persistent; do
    printf "%-25s" "$service"
    systemctl is-active "$service" 2>/dev/null || true
done

subsection "IPTables backend"
iptables --version 2>/dev/null || true

# ============================================================
# 6. PERSISTENCE DETECTION
# ============================================================

section "6. PERSISTENCE DETECTION"

subsection "Root cron jobs"
crontab -l -u root 2>/dev/null || echo "No root cron jobs"

subsection "System crontab"
cat /etc/crontab 2>/dev/null

subsection "Cron directories"
for dir in /etc/cron.d /etc/cron.hourly /etc/cron.daily \
           /etc/cron.weekly /etc/cron.monthly; do
    echo "--- $dir ---"
    ls -la "$dir" 2>/dev/null
done

subsection "Other user cron jobs"
while IFS=: read -r user _; do
    jobs=$(crontab -l -u "$user" 2>/dev/null)
    if [[ -n "$jobs" ]]; then
        echo "--- $user ---"
        echo "$jobs"
    fi
done < /etc/passwd

subsection "Systemd timers"
systemctl list-timers --all --no-pager

subsection "Enabled services"
systemctl list-unit-files --type=service --state=enabled --no-pager

subsection "Custom systemd service and timer files"
find /etc/systemd/system /usr/local/lib/systemd/system \
    -type f \( -name "*.service" -o -name "*.timer" \) \
    -ls 2>/dev/null

subsection "SSH authorized keys"
find /root /home -type f -name authorized_keys \
    -print -exec cat {} \; 2>/dev/null

subsection "SSH configuration files"
ls -la /etc/ssh/

subsection "Other startup mechanisms"
ls -la /etc/init.d/ 2>/dev/null
ls -l /etc/rc.local 2>/dev/null
atq 2>/dev/null

subsection "Recently modified systemd files (last 7 days)"
find /etc/systemd/system -type f -mtime -7 -ls 2>/dev/null

# ============================================================
# 7. LIGHTWEIGHT LOG INSPECTION
# ============================================================

section "7. LIGHTWEIGHT LOG INSPECTION"

subsection "Recent system errors (maximum 10)"
journalctl -p err -n 10 --no-pager 2>/dev/null

subsection "Recent authentication failures (maximum 10)"
if [[ -f /var/log/auth.log ]]; then
    grep -Ei 'failed password|invalid user|authentication failure' \
        /var/log/auth.log | tail -10
else
    echo "Authentication log unavailable"
fi

subsection "Recent successful SSH logins (maximum 5)"
if [[ -f /var/log/auth.log ]]; then
    grep -Ei 'accepted password|accepted publickey' \
        /var/log/auth.log | tail -5
else
    echo "Authentication log unavailable"
fi

subsection "Recent sudo activity (maximum 5)"
if [[ -f /var/log/auth.log ]]; then
    grep -i 'sudo:' /var/log/auth.log | tail -5
else
    echo "Authentication log unavailable"
fi

subsection "Recent kernel errors (maximum 10)"
dmesg -T 2>/dev/null |
grep -Ei 'error|fail|I/O error|out of memory' | tail -10

# ============================================================
# 8. SYSTEM HEALTH
# ============================================================

section "8. SYSTEM HEALTH"

subsection "Disk capacity"
df -hT

subsection "Inode capacity"
df -ih

subsection "Block devices"
lsblk -o NAME,SIZE,FSTYPE,TYPE,MOUNTPOINTS

subsection "Mounted filesystems"
findmnt

subsection "Memory"
free -h

subsection "CPU count"
nproc

subsection "Load average"
uptime

subsection "Failed services"
systemctl --failed --no-pager

subsection "Storage and filesystem warnings (maximum 10)"
journalctl -k -p warning -n 10 --no-pager 2>/dev/null

# ============================================================
# END
# ============================================================

section "FIRST15 COMPLETE"

echo "Host: $(hostname)"
echo "Date: $(date -Is)"

echo "========== END FIRST15 =========="
