Rocky Ecom  --  172.20.240.10  --  Rocky Linux 9
Login: sysadmin / Changeme1!      Public address: 172.25.(20+team#).10

SCORED HERE: HTTP (80), HTTPS (443), SSH, Ping. FTP may be here too -- CHECK.

GOTCHAS
 * firewalld + SELinux ENFORCING. Web server is 'httpd', not apache2.
 * The HTTP check compares PAGE CONTENT, not just 'is it up'. Load the page after any change.
 * If a service starts but can't read its files, suspect SELinux FIRST:
    getenforce ; ausearch -m avc -ts recent ; restorecon -Rv /var/www/html
 * NEVER run 'setenforce 0' to make an error go away.
 * If a DB backs the store, its password is in an app config file. Change both together.
 * NO SNAPSHOTS AND NO SCRUBS exist in this environment. Every change is permanent.
 * Rule 9: do NOT filter any public service by source IP. Penalty if detected.
 * Rule 12: do NOT block ICMP anywhere. Ping is scored.
 * Rule 11: you may change passwords, NEVER usernames.
END

RUN THESE, IN THIS ORDER
  1.  sudo bash harden.sh dry      read the plan, change nothing
  2.  sudo bash harden.sh          recon -> tripwires -> passwords -> ssh -> firewall
  3.  sudo bash watch.sh           watchdog + baseline, then loop every 15 min
  ...competition runs...
  4.  sudo bash clean.sh           evidence bundle FIRST, then teardown

ANY TIME SOMETHING FEELS WRONG
  sudo bash ../../persistence.sh          full hunt
  sudo bash ../../baseline.sh diff        what changed since hardening
  sudo bash ../../honeypot.sh alerts      tripwire hits
  sudo bash ../../splunk.sh check         still forwarding logs to 172.20.240.20?

IF YOU GET LOCKED OUT
  Firewall:  wait 5 min, it reverts itself.  Or: sudo bash ../../firewall.sh undo
  SSH:       the kit restores sshd_config automatically if the config fails its test.
             Console: cp /etc/ssh/sshd_config.bak.<newest> /etc/ssh/sshd_config
