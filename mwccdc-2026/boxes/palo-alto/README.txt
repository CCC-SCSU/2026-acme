Palo Alto  --  mgmt 172.20.240.200  --  PAN-OS 11.0.2
Login: admin / Changeme123      (inside 172.20.240.254, outside 172.16.0.1)

*** DO NOT RUN ANY SCRIPT FROM THIS KIT HERE. ***
PAN-OS is not Linux in any way this kit understands. Use the web UI:
    https://172.20.240.200

NO SNAPSHOTS, NO SCRUBS. If you break the firewall, every scored service behind
it goes dark and there is no revert.

ORDER OF WORK (web UI)
 1. Export the running config FIRST: Device > Setup > Operations > Export named
    configuration snapshot. Save it off-box before changing anything.
 2. Change the admin password (Device > Administrators). Create and TEST a second
    admin account before you touch the original one.
 3. Look for red team: extra admin accounts, unexpected security policies,
    changed NAT rules, unknown scheduled tasks.
 4. Commit often -- changes are not live until committed.

WHAT NOT TO DO
 * Do NOT add source-IP restrictions to public services. Rule 9 explicitly
   prohibits "knife edge" access that only permits the scoring engine, and
   source-IP filtering "may incur a penalty when detected."
 * Do NOT block ICMP. Ping is a scored service (rule 12).
 * Do NOT break the NAT that maps 172.25.(20+team#).x to 172.20.240.x. Every
   external scored check comes through it.
 * Do NOT restrict management access so hard that you lock yourselves out.
