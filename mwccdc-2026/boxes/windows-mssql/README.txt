2019 MSSQL  --  172.20.240.120  --  Windows Server 2019
Login: sysadmin / Changeme1!

NO SCRIPTS HERE. This kit is bash and Linux-only. Notes only.

SCORED HERE: MSSQL (1433), MSSQL SMB, MSSQL RDP.
The team pack notes for SMB: "competitors need to consider whether
authentication is for local or domain users."

WHAT THE LINUX TEAM NEEDS FROM YOU
 * If a Splunk forwarder runs here, keep it sending to 172.20.240.20:9997.
 * Tell us if you change anything that other boxes authenticate against.

RULES
 * Rule 11: passwords yes, usernames no.
 * Rule 9: no source-IP filtering. Rule 12: never block ICMP.
 * Submit password changes via Quotient PCR.
 * NO SNAPSHOTS, NO SCRUBS.
