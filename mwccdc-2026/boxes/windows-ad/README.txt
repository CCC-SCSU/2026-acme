2022 AD  --  172.20.240.100  --  Windows Server 2022
Login: sysadmin / Changeme1!

NO SCRIPTS HERE. This kit is bash and Linux-only. These are notes for whoever
owns this box, not something to run.

SCORED HERE: DNS, AD-WinRM. (DNS lookups are performed against this server.)

WHAT THE LINUX TEAM NEEDS FROM YOU
 * TELL US BEFORE YOU ROTATE AD PASSWORDS. The Ubuntu Email box authenticates
   POP3/IMAP against AD usernames. If you change them without warning, mail
   scoring dies on 172.20.240.15 and the owner there cannot see why.
 * If a Splunk universal forwarder runs here, keep it pointed at 172.20.240.20:9997
   and keep its service running. Check: Services -> SplunkForwarder.
 * Keep DNS answering. Several other checks depend on name resolution.

RULES THAT APPLY HERE TOO
 * Rule 11: you may change PASSWORDS, never USERNAMES.
 * Rule 9: no source-IP filtering on public services. Penalty if detected.
 * Rule 12: do not block ICMP.
 * Submit every password change at https://quotient.ccdc.events  (PCR tab,
   CSV format: username,password)
 * NO SNAPSHOTS, NO SCRUBS. Every change is permanent.
