# CCDC Windows scripts

Ten PowerShell 5.1 scripts for the DC playbook. Every script:

- runs from an **elevated** PowerShell (`Set-ExecutionPolicy Bypass -Scope Process -Force` first);
- writes its report to `C:\Backup\reports\<script>-<time>\` (CSV + transcript), so findings become incident-report evidence;
- keeps baselines in `C:\Backup\baselines\`. Once a baseline exists, later runs **diff against it automatically**;
- quarantines instead of deleting (`C:\Backup\quarantine\`).

## Where each one goes in the playbook

| When | Script | Replaces |
| --- | --- | --- |
| 0:05, own window, leave running | `watch-events.ps1` | watching Event Viewer by hand |
| 0:08 | `inventory-domain.ps1` (read-only) | finding hosts and service accounts by hand |
| 0:10 | `backup-all.ps1` | backup-dns.ps1 / backup-webfiles.ps1 |
| 0:12, before master.ps1 | `firewall-baseline-compare.ps1` | old firewall compare |
| 0:12, second window | `sfc-repair.ps1` | plain `sfc /scannow` |
| after master.ps1 | `audit-users-groups.ps1` | enumerate_user.ps1 |
| after reading the packet's password rules | `reset-passwords.ps1` | playbook's pcr.csv snippet |
| enumerate phase | `autoruns-baseline-compare.ps1`, `certificates-baseline-compare.ps1`, `hunt-user-files.ps1` | old autoruns/cert compares |
| after cleanup | re-run each with `-SaveBaseline` | |
| every 30-60 min | re-run each (auto-diff vs your baseline) | |

## Leave-running and team scripts

**`watch-events.ps1`** reads only new log records every 30 seconds and prints color-coded alerts. HIGH alerts beep, and every alert is appended to `C:\Backup\reports\watch-events-<host>-<date>.csv` for incident reports. It covers:
- **Accounts:** users created, enabled or deleted, privileged group adds, lockouts of scored accounts, password spraying and failed-logon bursts.
- **Kerberos:** Kerberoasting (RC4 tickets) and AS-REP roasting.
- **AD:** DCSync, AdminSDHolder, GPO and domain-root permission changes, shadow credentials, RBCD.
- **Persistence:** new services, scheduled tasks, and DNS plugin DLLs.
- **Tampering:** cleared logs, audit policy removed, Defender/firewall/Event Log stopped, Defender exclusions.
- **Execution:** suspicious command lines and PowerShell, and with Sysmon, LSASS dumping and injection.
- **Services:** DNS, AD DS, IIS or SQL stopping or crashing.

At start it lists audit subcategories that are off. `-EnableAuditing` turns them on, plus command-line and script-block logging. Other options:
- `-LookbackMinutes 60` also shows the last hour.
- Run it in its own window: `Start-Process powershell -ArgumentList '-NoExit -ExecutionPolicy Bypass -File C:\Tools\watch-events.ps1'`

**`inventory-domain.ps1`** is read-only. It lists every domain-joined Windows machine from AD (works even if the host is down), DNS, ping and a port check. It adds remote CIM details over WinRM or RPC when the host allows: OS and build, last boot, roles, NICs, listening ports with process, shares, local admins, key services, and services, tasks and IIS app pools that run as a domain account. `-Software` adds installed programs. It writes `summary.csv` and `report.html` (for inventory injects), `hosts.json`, and `service-accounts.txt`.

**`reset-passwords.ps1`** sets a new random password on every enabled account and writes `scoring-passwords.csv` for the ISE.
- **Always skipped:** Administrator, Guest, krbtgt, DefaultAccount, WDAGUtilityAccount (by RID, so renaming doesn't fool it), your own account, and `$` accounts.
- **Skip more:** `-Exclude svc_sql,'backup*'`, `-ExcludeFile <inventory>\service-accounts.txt`, or `-ExcludeGroup 'Service Accounts'`. It warns about likely service accounts you didn't exclude and about exclude patterns that match nobody.
- **Preview:** `-WhatIf` shows the list and changes nothing. Otherwise you must type RESET to continue.
- **How it runs:** it writes every password to a locked file before changing anything, clears "must change password", unlocks accounts, and tests each new password with a real login.
- **Match the ISE format:** `-UserColumn`, `-PasswordColumn`, `-Delimiter`, `-NoHeader`, `-DomainPrefix`. The file is UTF-8 without BOM.
- **Member servers:** `-Local` resets local accounts instead.
- **WRCCDC rule (2017 orientation):** only ONE digital mass password update is accepted. Confirm in the packet, run `-WhatIf` first, submit once.

## Scripts

**`sfc-repair.ps1`** checks that `sfc.exe` and `sfc_os.dll` are genuine before trusting them. It checks for a Microsoft signature that chains to a Microsoft root, a real PE header, and that the file isn't a renamed `cmd.exe`. It also looks for PATH, IFEO and SilentProcessExit hijacks and a broken TrustedInstaller service. A bad file is replaced from your kit, from WinSxS, or (with `-Online`) from Microsoft's symbol server via Winbindex hashes. Then it runs `sfc /scannow` by full path and summarizes CBS.log.
- Fixes ask for confirmation (Y/A). Add `-Confirm:$false` to skip the prompts.
- Sticky-keys backdoors: `.\sfc-repair.ps1 -Files sethc.exe,utilman.exe,osk.exe -NoScan`
- If no good copy is found: `-RunDism` (DISM RestoreHealth, 10-30 min) or `-Online`.

**`audit-users-groups.ps1`** prints every user with their direct groups and their effective privileged groups (nesting and primary group resolved). It flags:
- AS-REP roastable accounts, SPNs, delegation, SIDHistory, orphaned adminCount, passwords in descriptions;
- risky computers and MachineAccountQuota;
- dangerous AD permissions (DCSync, GenericAll, WriteDacl, add-member, shadow credentials, RBCD) on the domain root, AdminSDHolder, the DC OU and admin groups and accounts;
- GPO edit rights, user rights held by unexpected accounts (SeDebug, SeImpersonate, SeBackup...), and auto-logon passwords.

On a member server it audits local groups instead.

**`firewall-baseline-compare.ps1`** compares live rules against Windows' own factory rule set (the `SharedAccess\Defaults` registry key). It reports NEW, MODIFIED, ENABLED/DISABLED and GPO-pushed rules, ranked by risk: inbound allow from any address, programs in user folders, shells, C2 ports, and blocks on your scored ports. It also checks profiles, logging and the firewall services.

**`backup-all.ps1`** detects what the box runs and backs up DNS (zone files + record CSVs), AD (objects, group membership, GPOs, gPLinks, ACL SDDL, SYSVOL), IIS/web roots, SQL Server / MySQL / PostgreSQL, and the firewall policy. It writes a SHA256 `manifest.csv` and a `RESTORE.txt` cheat sheet.
- **Write the manifest hash it prints on paper.** `.\backup-all.ps1 -Verify <folder>` proves later whether red team touched the backup.
- Options: `-Zip`, `-CopyTo E:\`, `-SystemState -SystemStateTarget E:`, `-IncludeNtdsIfm` (every password hash in the domain; move it off the box), `-ExportIisCerts`.
- Database passwords are prompted for and never typed on the command line. Use `-NoDatabasePrompt` to skip the prompts.

**`autoruns-baseline-compare.ps1`** runs autorunsc and refuses to run it unless it's Microsoft-signed. It keeps Microsoft entries visible and scores every command line: LOLBins, encoded or download keywords, URLs and IPs, user-writable paths, system-process names outside System32, WMI. It also finds scheduled tasks hidden by deleting their security descriptor. Needs `autorunsc64.exe` next to the script or in `C:\Tools`. Run it as SYSTEM (`psexec -s -i powershell`) for the full hidden-task check.

**`certificates-baseline-compare.ps1`** flags trusted roots that aren't in Microsoft's root program (`-Offline` skips the download), shows whether each came from GPO or AD, and reports TrustedPublisher/TrustedPeople entries, code-signing certs and rogue CAs in the AD NTAuth store. `-Remove <thumbprint>` exports the cert, then deletes it.

**`hunt-user-files.ps1`** scans user profiles, temp folders, ProgramData, the Recycle Bin, `spool\drivers\color`, web roots and loose files at C:\ root. It scores each file by type, tool name (mimikatz, rubeus, chisel...), executables hiding behind other extensions, double extensions, Startup folders, alternate data streams, web-shell and script keywords, and broken signatures. Try `-Days 2 -IncludeAllRecent` for everything touched recently.

## Tonight (before Saturday)

1. On a Windows VM: `powershell -ExecutionPolicy Bypass -File .\check-scripts.ps1`. It runs the real parser and load test (these were only checked statically).
2. Do a full dry run of each script on a practice DC.
3. On a clean VM of each OS you expect (Server 2016/2019/2022):
   - `.\sfc-repair.ps1 -BuildKit -Kit E:\kit`: known-good copies + SHA256 list of sfc and the sticky-keys targets. Bring the kit with your tools and pass `-Kit` in competition.
   - `-SaveBaseline -OutDir E:\clean\<os>` on the autoruns, certificate and firewall scripts. In competition, pass `-Baseline E:\clean\<os>\baselines\<file>` to see only what differs from a clean install.
