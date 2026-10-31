This is the Ubuntu DB server with ip : 192.168.220.199.


Login with given credentials.Change the permissions to execute and run the first15 script:

```python
chmod +x marvinfirst15.sh
sudo ./marvinfirst15.sh > marvinfirst15.log 2>&1
```

**1. First you have to confirm identify,**

Confirm the Ubuntu release, kernel, current account, and privilege level.
Check uptime and load for signs of a recent reboot or resource pressure.
See current and recent login sessions. Notice unfamiliar names or addresses.

```python
hostname
hostnamectl
cat /etc/os-release
uname -a
date -Is
uptime
whoami
id
who
w
last -n 15
```
**2. Check Host accounts and SSH access**

Display local/directory accounts, privileged groups, recent logins, and selected effective SSH settings when sshd is installed. Change admin credentials

```python
######## check admin groups  #######
getent passwd	#All accounts known through the system's configured account sources
getent group sudo	#Members of the sudo group
getent group adm	#Members of the adm group, often able to read certain logs
getent group docker	#Members of the docker group, which can effectively grant root-level control
last -n 15	#Recent login history
lastb -n 15	#Recent failed login attempts, if failure logging is enabled
who	#Users currently logged in
w	#Logged-in users and what they are doing
id username	#A particular user's UID, GID, and group memberships
passwd -S username	#Password status for a particular account
chage -l username	#Password aging and account-expiration information
getent shadow	#Shadow account records, if permitted; avoid printing password hashes into your competition logs
sshd -T	#Effective SSH server configuration
sudo ls -la /etc/sudoers.d/ #check sudoers group
```

Find accounts with login shell:
```python
awk -F: '$7 !~ /(nologin|false)$/ {print $1, $3, $6, $7}' /etc/passwd
```
Find Unexpected accounts with UID 0 (root-equivalent)

```python
awk -F: '$3 == 0 {print $1, $3, $6, $7}' /etc/passwd
```

Change account password and username:

```python
sudo passwd root #change root passw
sudo usermod -l newadmin admin #change username
sudo usermod -d /home/newadmin -m newadmin #rename and move home dir
sudo adduser newadmin #create new user and add to sudoers
sudo usermod -aG sudo newadmin
```

Disable suspicious users:


**3. Find interfaces routes and open ports**

- Identify the server's addresses and default route.
- See which TCP and UDP ports are listening and, where permissions allow, the owning process.
- Compare exposed ports with the database and application role you expect.

**Common database port numbers:**
Port	Common database
3306	MySQL / MariaDB
5432	PostgreSQL
27017	MongoDB
6379	Redis
1433	Microsoft SQL Server
1521	Oracle
9042	Cassandra
5984	CouchDB
9200	Elasticsearch

```python
ip -brief address
ip route #find routing table, routes and gateways
ip neigh #find neighbors and ARP table

ss -lntup #find listening TCP/UDP ports -antup
netstat -anp #find listening and established connections
```

**4. Identify the DB**

find which database service is running

```python
systemctl --no-pager --type=service --state=running #list of currently running systemd services
systemctl --no-pager --failed #list of failed systemd services
systemctl list-units --all --type=service #list all services, even inactive ones
ps -eo user,pid,ppid,stat,%cpu,%mem,comm --sort=-%cpu #list all processes, sorted by CPU usage
ps -eo user,pid,ppid,stat,%cpu,%mem,comm --sort=-%mem #list all processes, sorted by memory usage
#find installed packages to see which db is installed
dpkg-query -W -f='${binary:Package}\t${Version}\n' 2>/dev/null |
grep -Ei 'mysql|mariadb|postgres|mongodb|redis|mssql|sqlite|cassandra|couchdb|elasticsearch|influxdb|clickhouse' || true
```
**5. Review Host firewall state**

```python
ufw status verbose #check firewall status
sudo nft -a list ruleset #check nftables ruleset to reveal more firewall rules
iptables -S #display iptables rules , use ip6tables for ipv6
iptables -L -n -v #display iptables rules with verbose output
```


**6. Look for persistence**

```python
crontab -l
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.hourly/
ls -la /etc/cron.daily/
systemctl list-timers --all
```
**7. Check recent errors and logs**

Look for failed starts, storage problems, authentication failures, crashes, and repeated errors.
```python
journalctl -p warning -n 60 --no-pager
journalctl -u mysql -n 40 --no-pager #replace mysql with db service name
tail -n 50 /var/log/auth.log
```
**8. Check capacity and summarize findings**

Full disks, low memory, or failed mounts can cause database and application outages.

```python
df -hT #disk usage
free -h #memory usage
lsblk #block devices
findmnt #mounted filesystems
systemctl --failed --no-pager #failed mounts
systemctl is-active mysql # check if db is running, replace with db service
systemctl status mysql --no-pager
```

**9. Backup db**

```python
sudo mkdir -p /root/db-backups # create backup dir
sudo chmod 700 /root/db-backups
sudo sh -c 'mysqldump --all-databases --single-transaction --routines --triggers --events > /root/db-backups/mysql-full-backup.sql' #for mysql backup
sudo ls -lh /root/db-backups/ # check if backup created
# hash the backup and check if it's been change
sudo find /root/db-backups -type f -exec ls -lh {} \;

sudo sha256sum /root/db-backups/*

sudo chmod 600 /root/db-backups/*
```