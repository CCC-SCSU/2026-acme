Ubuntu Workstation  --  dhcp  --  Ubuntu
Login: sysadmin / Changeme1!      Public address: 172.25.(20+team#).x

SCORED HERE: Probably nothing scored. It is a workstation.

GOTCHAS
 * Rule 11: workstations may NOT be re-tasked. Do not move services onto it.
 * Low priority. Change the password, run the hunt, move on.
 * Run 'firewall.sh suggest' before firewalling -- if nothing is scored here,
 * a default-deny inbound rule is low risk, but confirm first.
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
