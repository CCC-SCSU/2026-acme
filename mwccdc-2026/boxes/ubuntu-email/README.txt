Ubuntu Email  --  172.20.240.15  --  Ubuntu 22.04
Login: sysadmin / Changeme1!      Public address: 172.25.(20+team#).15

SCORED HERE: SMTP (25), POP3 (110), IMAP (143), webmail, SSH, Ping.

GOTCHAS
 * *** POP3/IMAP AUTHENTICATE AGAINST ACTIVE DIRECTORY USERNAMES. ***
 * If the Windows team rotates AD passwords, mail scoring breaks on THIS box.
 * Talk to them before either of you changes anything.
 * The checks SEND AND RECEIVE real mail -- a listening port is not enough.
 * Add 80/443 if webmail is served here. Check with 'firewall.sh suggest' first.
 * ufw may be active. If so, do not also use the kit firewall -- pick one.
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
