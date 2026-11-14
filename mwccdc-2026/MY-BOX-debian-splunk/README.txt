MY BOX  --  Debian Splunk  --  172.20.240.20  --  Debian 12 + Splunk 10
Login: sysadmin / Changeme1!       Public: 172.25.(20+team#).20

SCORED HERE: Splunk Query (8000), Splunk Management (8089), SSH, Ping.
ALSO CRITICAL: 9997 inbound -- every other box forwards its logs to you.

GOTCHAS
 * DO NOT BLOCK 9997 or 514. Break those and the whole network stops logging,
   which costs you the 20% of the score that is incident response.
 * The Splunk Query check AUTHENTICATES and searches for specific content. If you
   change the Splunk admin password, submit it via Quotient PCR or the check fails.
 * SPLUNK 10 COLD-START RACE (confirmed 13 Nov): after a reboot or a restart,
   splunkd can come up with the WEB TIER DOWN. 8089 and 9997 look fine but 8000 --
   the scored Query check -- never opens. The log shows:
       WebuiStartup ... Connection refused ... 127.0.0.1:8065
   FIX: sudo systemctl restart Splunkd   then wait ~2 minutes and re-check 8000.
   ALWAYS CHECK 8000 AFTER ANY RESTART. 'systemctl is-active' says the unit is up,
   NOT that the scored port is open.
 * BOOT-START: if 'splunk.sh check' says "managed by: NOTHING", Splunk will not
   survive a reboot and red team CAN reboot you. Fixing it is not free though --
   it caused the 8000 race above. If it is already systemd-managed with 8000
   listening, LEAVE IT ALONE.
   To fix it (stop as the OWNING user, enable as root):
       ps -o user= -p $(pgrep -x splunkd | head -1)      # usually 'splunk'
       sudo -u splunk /opt/splunk/bin/splunk stop
       sudo /opt/splunk/bin/splunk enable boot-start -systemd-managed 1 -user splunk
       sudo systemctl daemon-reload ; sudo systemctl enable --now Splunkd
       ss -tlnp | grep -E ':8000|:8065'                  # BOTH must be listening
 * Debian 12 may have nftables and no working iptables. The kit detects this and
   builds its own 'inet ccdc' table, leaving your other tables alone.
 * NO SNAPSHOTS, NO SCRUBS. Every change is permanent.
 * Rule 9: no source-IP filtering. Rule 12: never block ICMP. Rule 11: no username changes.
END

RUN THESE, IN THIS ORDER
  0.  sudo bash ../probe.sh | head -60     30 sec, read-only: does this box match?
      sudo bash ../splunk.sh check         is Splunk healthy? is 8000 up?
  1.  sudo bash harden.sh dry              read the plan, change nothing
  2.  sudo bash harden.sh                  the guided sequence
  3.  sudo bash watch.sh                   Splunk health + watchdog + baseline
  ...competition runs...
  4.  sudo bash clean.sh                   evidence FIRST, then teardown

YOUR UNIQUE JOB: you are the indexer. Run this every 15 minutes --
      sudo bash ../splunk.sh indexer
Any box missing from that list is NOT forwarding. Only you can see it. Tell that
box's owner immediately.

USEFUL SPLUNK SEARCHES (for incident reports -- 20% of the score)
  index=* "Failed password"                 SSH brute force
  index=* "Accepted password"               logins -- any you did not make?
  index=* sudo                              privilege escalation
  | metadata type=hosts                     who is reporting in at all
