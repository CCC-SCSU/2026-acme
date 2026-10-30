<#
.SYNOPSIS
    Leave-it-running event watcher: every 30 seconds it reads only the NEW records in each log and alerts on
    attacker activity. Read-only unless you pass -EnableAuditing.

.DESCRIPTION
    Run it in its own PowerShell window and leave it open (Ctrl+C to stop). It alerts on:
      Accounts    user created / enabled / deleted, password reset, computer account created, account locked out
                  (scored accounts break!), member added to a group (HIGH for privileged groups),
                  failed-logon bursts and password spraying
      Kerberos    RC4 service tickets (Kerberoasting), TGTs issued without pre-auth (AS-REP roasting)
      AD          DCSync (replication rights used by a non-DC account), changes to AdminSDHolder, GPOs, GPO links,
                  domain-root permissions and sensitive attributes (SPN, shadow credentials, RBCD, logon script)
      Persistence new services (4697 / 7045), scheduled tasks (4698 / 4702 / TaskScheduler 106),
                  DNS server plugin DLL loaded (DnsAdmins attack)
      Tampering   Security / other logs cleared, audit policy removed, Defender / firewall / Event Log / Sysmon
                  stopped or disabled, Defender exclusions added or protection turned off, Defender detections
      Execution   suspicious command lines (4688, or Sysmon 1 when Sysmon is installed), LSASS memory access and
                  remote thread injection (Sysmon 10 / 8), LOLBin network connections (Sysmon 3), PowerShell
                  script blocks Windows flags as suspicious or that match attack keywords (4104)
      Services    scored-type services (DNS, AD DS, KDC, Netlogon, IIS, SQL...) stopping or crashing
    HIGH alerts beep. Repeats of the same alert by the same account in one poll collapse into one line.
    Every alert is appended to C:\Backup\reports\watch-events-<date>.csv for incident reports.
    At start it checks the audit policy and names any subcategory that is off (those events can never appear).

    Notes: DCSync (4662) also needs an audit entry (SACL) on the domain root; test it in practice.
    Script block text (4104) from scripts in this script's own folder is ignored, so your tools don't alert.

.EXAMPLE
    .\watch-events.ps1
.EXAMPLE
    .\watch-events.ps1 -LookbackMinutes 60        # first show what happened in the last hour
.EXAMPLE
    .\watch-events.ps1 -EnableAuditing            # turn on missing audit subcategories + command-line and script block logging
.EXAMPLE
    Start-Process powershell -ArgumentList '-NoExit -ExecutionPolicy Bypass -File C:\Tools\watch-events.ps1'
#>
[CmdletBinding()]
param(
    [ValidateRange(5, 3600)][int]$IntervalSeconds = 30,
    [int]$LookbackMinutes = 0,
    [ValidateSet('INFO', 'MED', 'HIGH')][string]$MinSeverity = 'INFO',
    [int]$SprayThreshold = 15,
    [switch]$NoBeep,
    [switch]$EnableAuditing,
    [string]$OutDir = 'C:\Backup'
)

function Write-Section([string]$Text) { Write-Host ''; Write-Host ('=== {0} ===' -f $Text) -ForegroundColor Cyan }
function Write-Good([string]$Text) { Write-Host ('[+] {0}' -f $Text) -ForegroundColor Green }
function Write-Warn([string]$Text) { Write-Host ('[!] {0}' -f $Text) -ForegroundColor Yellow }
function Write-Bad([string]$Text)  { Write-Host ('[X] {0}' -f $Text) -ForegroundColor Red }
function Write-Info([string]$Text) { Write-Host ('[*] {0}' -f $Text) }
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Get-SevRank([string]$Sev) { switch ($Sev) { 'HIGH' { 3 } 'MED' { 2 } 'INFO' { 1 } default { 0 } } }

# ---------------------------------------------------------------- detection content
$script:LogSecurity = 'Security'
$script:LogSystem = 'System'
$script:LogPowerShell = 'Microsoft-Windows-PowerShell/Operational'
$script:LogDefender = 'Microsoft-Windows-Windows Defender/Operational'
$script:LogSysmon = 'Microsoft-Windows-Sysmon/Operational'
$script:LogTasks = 'Microsoft-Windows-TaskScheduler/Operational'
$script:LogDns = 'DNS Server'

$script:PrivGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators',
    'Backup Operators', 'Server Operators', 'Print Operators', 'DnsAdmins', 'Group Policy Creator Owners', 'Key Admins',
    'Enterprise Key Admins', 'Remote Desktop Users', 'Remote Management Users', 'Cert Publishers', 'Hyper-V Administrators',
    'Distributed COM Users', 'Event Log Readers')
$script:ReplRegex = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c'
$script:SensitiveAttrs = @('servicePrincipalName', 'msDS-KeyCredentialLink', 'msDS-AllowedToActOnBehalfOfOtherIdentity',
    'msDS-AllowedToDelegateTo', 'scriptPath', 'sIDHistory', 'msDS-SupportedEncryptionTypes', 'altSecurityIdentities')

# Command lines: HIGH = credential theft, download/obfuscation, tampering, adding users; MED = recon / lateral movement.
$script:CmdHigh = '(?i)(\s-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{20,})|frombase64string|downloadstring|downloadfile|net\.webclient|invoke-webrequest|\biwr\b|start-bitstransfer|invoke-expression|\biex\b|mimikatz|sekurlsa|lsadump|procdump.*lsass|comsvcs(\.dll)?.{0,40}minidump|ntdsutil.*(ifm|snapshot)|vssadmin.*(create|delete)\s+shadow|wbadmin\s+delete|reg(\.exe)?\s+save\s+hklm\\(sam|system|security)|certutil.*(urlcache|-decode)|bitsadmin.*/transfer|net1?(\.exe)?\s+user\s+\S+\s+\S+\s+/add|net1?(\.exe)?\s+(local)?group\s+.*\s/add|add-mppreference|set-mppreference.*disable|wevtutil(\.exe)?\s+cl|clear-eventlog|mshta(\.exe)?\s+(http|javascript|vbscript)|regsvr32.*/i:http|rundll32.*javascript:'
$script:CmdMed = '(?i)schtasks(\.exe)?\s+/create|\bsc(\.exe)?\s+\\\\|\bsc(\.exe)?\s+(create|config)|wmic.*process\s+call\s+create|wmic(\.exe)?\s+/node|nltest.*(/dclist|/domain_trusts)|whoami(\.exe)?\s+/(priv|all|groups)|psexe(c|svc)|\\\\[^\\\s]+\\(admin|c)\$|net1?(\.exe)?\s+(view|share|session)|setspn.*\s-q|dsquery|adfind|cmdkey(\.exe)?\s+/list|reg(\.exe)?\s+add.*\\(run|winlogon|image file execution options)'
$script:PsRegex = '(?i)mimikatz|sekurlsa|lsadump|invoke-kerberoast|rubeus|sharphound|bloodhound|powerview|get-domaintrust|invoke-sharefinder|invoke-userhunter|add-mppreference\s+-exclusion|set-mppreference\s+-disable|downloadstring|downloadfile|net\.webclient|frombase64string|reflection\.assembly\]::load|virtualalloc|amsiutils|amsiinitfailed|invoke-shellcode|invoke-reflectivepeinjection|out-minidump|get-gpppassword|invoke-dcsync|net\.sockets\.tcpclient'
$script:LolbinRegex = '(?i)\\(powershell|pwsh|rundll32|regsvr32|mshta|certutil|bitsadmin|wscript|cscript|msbuild|installutil|cmd|notepad|wmic)\.exe$'
$script:LsassSafe = '(?i)\\(MsMpEng|csrss|wininit|lsm|services|svchost|WmiPrvSE|vmtoolsd|MsSense|SenseIR|procexp64|procexp|Sysmon64|Sysmon|MRT|smartscreen)\.exe$'
$script:SecuritySvc = '(?i)Defender|Firewall|Windows Event Log|Sysmon|Base Filtering Engine|Security Center|Wazuh|Splunk'
$script:CoreSvc = '(?i)^(DNS Server|Active Directory Domain Services|Kerberos Key Distribution Center|Netlogon|Active Directory Web Services|World Wide Web Publishing Service|Windows Process Activation Service|SQL Server.*|DHCP Server|DFS Replication|Remote Desktop Services|Windows Remote Management.*|Microsoft FTP Service|IIS Admin Service|MySQL.*|Apache.*|postgresql.*)$'

# Audit subcategories each detection needs (GUIDs are language-independent).
$script:AuditChecks = @(
    @{ Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Name = 'User Account Management'; Need = 'Success'; Events = '4720 4722 4724 4726 4740' },
    @{ Guid = '{0CCE9236-69AE-11D9-BED3-505054503030}'; Name = 'Computer Account Management'; Need = 'Success'; Events = '4741' },
    @{ Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Name = 'Security Group Management'; Need = 'Success'; Events = '4728 4732 4756' },
    @{ Guid = '{0CCE9240-69AE-11D9-BED3-505054503030}'; Name = 'Kerberos Service Ticket Operations'; Need = 'Success'; Events = '4769' },
    @{ Guid = '{0CCE9242-69AE-11D9-BED3-505054503030}'; Name = 'Kerberos Authentication Service'; Need = 'Success'; Events = '4768' },
    @{ Guid = '{0CCE923B-69AE-11D9-BED3-505054503030}'; Name = 'Directory Service Access'; Need = 'Success'; Events = '4662' },
    @{ Guid = '{0CCE923C-69AE-11D9-BED3-505054503030}'; Name = 'Directory Service Changes'; Need = 'Success'; Events = '5136' },
    @{ Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Name = 'Process Creation'; Need = 'Success'; Events = '4688' },
    @{ Guid = '{0CCE9211-69AE-11D9-BED3-505054503030}'; Name = 'Security System Extension'; Need = 'Success'; Events = '4697' },
    @{ Guid = '{0CCE9227-69AE-11D9-BED3-505054503030}'; Name = 'Other Object Access Events'; Need = 'Success'; Events = '4698 4702' },
    @{ Guid = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Name = 'Audit Policy Change'; Need = 'Success'; Events = '4719' },
    @{ Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Name = 'Logon'; Need = 'Failure'; Events = '4625' }
)
$script:AuditNames = @{}
foreach ($c in $script:AuditChecks) { $script:AuditNames[$c.Guid] = $c.Name }

# ---------------------------------------------------------------- helpers
$script:SidCache = @{}
function Resolve-SidName([string]$Sid) {
    if (-not $Sid -or $Sid -eq '-') { return '' }
    if ($script:SidCache.ContainsKey($Sid)) { return $script:SidCache[$Sid] }
    $n = $Sid
    try { $n = (New-Object Security.Principal.SecurityIdentifier($Sid)).Translate([Security.Principal.NTAccount]).Value } catch { }
    $script:SidCache[$Sid] = $n
    $n
}

function Get-Fields($E) {
    # EventData (named Data elements) and UserData (log-cleared events) into one hashtable.
    $h = @{}
    try {
        $x = [xml]$E.ToXml()
        foreach ($n in $x.DocumentElement.ChildNodes) {
            if ($n.LocalName -eq 'EventData') {
                foreach ($d in $n.ChildNodes) {
                    if ($d.LocalName -eq 'Data') { $nm = $d.GetAttribute('Name'); if ($nm) { $h[$nm] = $d.InnerText } }
                }
            } elseif ($n.LocalName -eq 'UserData' -and $n.FirstChild) {
                foreach ($d in $n.FirstChild.ChildNodes) { if ($d.NodeType -eq 'Element') { $h[$d.LocalName] = $d.InnerText } }
            }
        }
    } catch { }
    $h
}

function Get-Val($D, [string]$Key) { if ($D.ContainsKey($Key) -and $null -ne $D[$Key]) { return [string]$D[$Key] } ''; }
function Get-Who($D) {
    $u = Get-Val $D 'SubjectUserName'; $dom = Get-Val $D 'SubjectDomainName'
    if (-not $u -or $u -eq '-') { return '' }
    if ($dom -and $dom -ne '-') { return ('{0}\{1}' -f $dom, $u) }
    $u
}
function Get-Target($D) {
    $u = Get-Val $D 'TargetUserName'; $dom = Get-Val $D 'TargetDomainName'
    if ($dom -and $dom -ne '-') { return ('{0}\{1}' -f $dom, $u) }
    $u
}
function Get-Short([string]$Text, [int]$Max = 220) {
    $t = (([string]$Text) -replace '\s+', ' ').Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + '...' }
    $t
}

function New-Alert($E, [string]$Sev, [string]$Title, [string]$Who, [string]$Target, [string]$Detail) {
    [pscustomobject]@{
        Time = $E.TimeCreated; Severity = $Sev; Title = $Title; Who = $Who; Target = $Target; Detail = (Get-Short $Detail 300)
        Log = $E.LogName; EventId = $E.Id; RecordId = $E.RecordId; Computer = $E.MachineName
    }
}
function New-PlainAlert([string]$Sev, [string]$Title, [string]$Detail) {
    [pscustomobject]@{ Time = (Get-Date); Severity = $Sev; Title = $Title; Who = ''; Target = ''; Detail = $Detail
                       Log = ''; EventId = ''; RecordId = ''; Computer = $env:COMPUTERNAME }
}

function Get-LatestRecordId([string]$Log) {
    try { return [int64](Get-WinEvent -LogName $Log -MaxEvents 1 -ErrorAction Stop).RecordId } catch { return $null }
}

function Get-StartCursor([string]$Log, [int]$Minutes) {
    $latest = Get-LatestRecordId $Log
    if ($null -eq $latest) { return [int64]0 }
    if ($Minutes -le 0) { return $latest }
    try {
        $first = Get-WinEvent -FilterHashtable @{ LogName = $Log; StartTime = (Get-Date).AddMinutes(-$Minutes) } -Oldest -MaxEvents 1 -ErrorAction Stop
        return ([int64]$first.RecordId - 1)
    } catch { return $latest }
}

$script:QueryWarned = @{}
function Read-Window {
    param([string]$Log, [int[]]$Ids, [int64]$After, [int64]$UpTo, [string]$SysFilter = '', [string]$DataFilter = '')
    $idPart = (@($Ids) | ForEach-Object { 'EventID={0}' -f $_ }) -join ' or '
    $xp = '*[System[({0}) and EventRecordID > {1} and EventRecordID <= {2}{3}]{4}]' -f $idPart, $After, $UpTo, $SysFilter, $DataFilter
    try { return @(Get-WinEvent -LogName $Log -FilterXPath $xp -Oldest -ErrorAction Stop) }
    catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*' -and -not $script:QueryWarned.ContainsKey($xp)) {
            $script:QueryWarned[$xp] = $true
            Write-Host ''
            Write-Warn ('Query on {0} failed: {1}' -f $Log, $_.Exception.Message)
        }
        return @()
    }
}

# ---------------------------------------------------------------- event -> alert rules
function Convert-Event($E) {
    $d = Get-Fields $E
    $who = Get-Who $d
    switch ('{0}|{1}' -f $E.LogName, $E.Id) {
        # --- accounts
        'Security|4720' { New-Alert $E 'HIGH' 'User account created' $who (Get-Target $d) '' }
        'Security|4722' { New-Alert $E 'MED' 'User account enabled' $who (Get-Target $d) '' }
        'Security|4724' { New-Alert $E 'INFO' 'Password reset' $who (Get-Target $d) '' }
        'Security|4726' { New-Alert $E 'MED' 'User account deleted' $who (Get-Target $d) '' }
        'Security|4741' { New-Alert $E 'HIGH' 'Computer account created (MachineAccountQuota / RBCD abuse?)' $who (Get-Target $d) '' }
        'Security|4740' { New-Alert $E 'MED' 'Account LOCKED OUT (scored account?)' '' (Get-Val $d 'TargetUserName') ('caller: ' + (Get-Val $d 'TargetDomainName')) }
        { $_ -in 'Security|4728', 'Security|4732', 'Security|4756' } {
            $grp = Get-Val $d 'TargetUserName'
            $member = Get-Val $d 'MemberName'
            if ($member -match '^CN=((?:\\,|[^,])+)') { $member = $Matches[1] -replace '\\,', ',' }
            if (-not $member -or $member -eq '-') { $member = Resolve-SidName (Get-Val $d 'MemberSid') }
            $sev = 'MED'
            if ($script:PrivGroups -contains $grp) { $sev = 'HIGH' }
            New-Alert $E $sev ('Member added to group "{0}"' -f $grp) $who $member ''
        }
        # --- persistence
        'Security|4697' { New-Alert $E 'HIGH' 'Service installed' $who (Get-Val $d 'ServiceName') ('{0} | runs as {1}' -f (Get-Val $d 'ServiceFileName'), (Get-Val $d 'ServiceAccount')) }
        { $_ -in 'Security|4698', 'Security|4702' } {
            $task = Get-Val $d 'TaskName'
            $xml = Get-Val $d 'TaskContent'
            $cmd = ([regex]::Match($xml, '<Command>(.*?)</Command>', 'Singleline')).Groups[1].Value
            $args2 = ([regex]::Match($xml, '<Arguments>(.*?)</Arguments>', 'Singleline')).Groups[1].Value
            $runAs = ([regex]::Match($xml, '<UserId>(.*?)</UserId>', 'Singleline')).Groups[1].Value
            $isMs = $task -like '\Microsoft\*'
            if ($E.Id -eq 4702 -and $isMs) { return }
            $sev = 'HIGH'; $title = 'Scheduled task created'
            if ($E.Id -eq 4702) { $sev = 'MED'; $title = 'Scheduled task changed' }
            if ($isMs -and $E.Id -eq 4698) { $sev = 'MED' }
            New-Alert $E $sev $title $who $task ('{0} {1} | runs as {2}' -f $cmd, $args2, (Resolve-SidName $runAs))
        }
        # --- tampering
        'Security|1102' { New-Alert $E 'HIGH' 'SECURITY LOG CLEARED' $who 'Security' '' }
        'Security|4719' {
            $guid = Get-Val $d 'SubcategoryGuid'
            $name = $guid
            if ($script:AuditNames.ContainsKey($guid)) { $name = $script:AuditNames[$guid] }
            $chg = (Get-Val $d 'AuditPolicyChanges') -replace '%%8448', 'Success removed' -replace '%%8449', 'Success added' -replace '%%8450', 'Failure removed' -replace '%%8451', 'Failure added'
            $sev = 'INFO'
            if ($chg -match 'removed') { $sev = 'HIGH' }
            New-Alert $E $sev 'Audit policy changed' $who $name $chg
        }
        # --- execution
        'Security|4688' {
            $cmd = Get-Val $d 'CommandLine'
            if (-not $cmd) { $cmd = Get-Val $d 'NewProcessName' }
            if ($cmd -match $script:CmdHigh) { New-Alert $E 'HIGH' 'Suspicious command' $who (Split-Path -Leaf (Get-Val $d 'NewProcessName')) $cmd }
            elseif ($cmd -match $script:CmdMed) { New-Alert $E 'MED' 'Recon / lateral-movement command' $who (Split-Path -Leaf (Get-Val $d 'NewProcessName')) $cmd }
        }
        # --- AD changes
        'Security|5136' {
            if ((Get-Val $d 'OperationType') -ne '%%14674') { return }   # only "value added", halves the noise
            $attr = Get-Val $d 'AttributeLDAPDisplayName'
            $dn = Get-Val $d 'ObjectDN'
            $cls = Get-Val $d 'ObjectClass'
            $cn = $dn
            if ($dn -match '^CN=((?:\\,|[^,])+)') { $cn = $Matches[1] }
            if ($dn -like 'CN=AdminSDHolder,*') { New-Alert $E 'HIGH' 'AdminSDHolder modified (persistent admin backdoor?)' $who $attr '' }
            elseif ($attr -eq 'nTSecurityDescriptor' -and $script:DomainDN -and $dn -eq $script:DomainDN) { New-Alert $E 'HIGH' 'Domain root permissions changed (DCSync rights?)' $who $dn '' }
            elseif ($script:SensitiveAttrs -contains $attr) { New-Alert $E 'HIGH' ('Sensitive attribute set: {0}' -f $attr) $who $cn (Get-Val $d 'AttributeValue') }
            elseif ($cls -eq 'groupPolicyContainer') { New-Alert $E 'MED' 'GPO changed' $who $cn $attr }
            elseif ($attr -eq 'gPLink') { New-Alert $E 'MED' 'GPO link changed' $who $cn (Get-Val $d 'AttributeValue') }
            elseif ($attr -eq 'nTSecurityDescriptor') { New-Alert $E 'MED' 'Permissions changed on AD object' $who $cn '' }
        }
        'Security|4662' {
            $u = Get-Val $d 'SubjectUserName'
            if ($u.EndsWith('$')) { return }   # domain controllers replicating normally
            if ((Get-Val $d 'Properties') -match $script:ReplRegex) { New-Alert $E 'HIGH' 'DCSync: replication rights used by a non-DC account' $who (Get-Val $d 'ObjectName') '' }
        }
        # --- Kerberos
        'Security|4769' {
            $svc = Get-Val $d 'ServiceName'
            if ($svc.EndsWith('$') -or $svc -like 'krbtgt*' -or (Get-Val $d 'Status') -ne '0x0') { return }
            New-Alert $E 'HIGH' 'RC4 service ticket requested (Kerberoasting?)' (Get-Val $d 'TargetUserName') $svc ('from ' + (Get-Val $d 'IpAddress'))
        }
        'Security|4768' {
            if ((Get-Val $d 'Status') -ne '0x0') { return }
            New-Alert $E 'HIGH' 'TGT issued without pre-auth (AS-REP roasting?)' '' (Get-Val $d 'TargetUserName') ('from ' + (Get-Val $d 'IpAddress'))
        }
        # --- System log
        'System|7045' { New-Alert $E 'HIGH' 'Service installed' (Resolve-SidName ([string]$E.UserId)) (Get-Val $d 'ServiceName') ('{0} | runs as {1}' -f (Get-Val $d 'ImagePath'), (Get-Val $d 'AccountName')) }
        'System|104' { New-Alert $E 'HIGH' 'EVENT LOG CLEARED' ('{0}\{1}' -f (Get-Val $d 'SubjectDomainName'), (Get-Val $d 'SubjectUserName')) (Get-Val $d 'Channel') '' }
        'System|7036' {
            $svc = Get-Val $d 'param1'
            if ((Get-Val $d 'param2') -notmatch '(?i)stop') { return }
            if ($svc -match $script:SecuritySvc) { New-Alert $E 'HIGH' 'Security service STOPPED' '' $svc '' }
            elseif ($svc -match $script:CoreSvc) { New-Alert $E 'MED' 'Core / scored service stopped' '' $svc '' }
        }
        'System|7040' {
            $svc = Get-Val $d 'param1'
            if ((Get-Val $d 'param3') -match '(?i)disabl' -and ($svc -match $script:SecuritySvc -or $svc -match $script:CoreSvc)) {
                New-Alert $E 'HIGH' 'Service DISABLED' (Resolve-SidName ([string]$E.UserId)) $svc ('{0} -> {1}' -f (Get-Val $d 'param2'), (Get-Val $d 'param3'))
            }
        }
        { $_ -in 'System|7031', 'System|7034' } { New-Alert $E 'MED' 'Service crashed' '' (Get-Val $d 'param1') '' }
        # --- Defender
        'Microsoft-Windows-Windows Defender/Operational|1116' { New-Alert $E 'HIGH' ('Defender detected: {0}' -f (Get-Val $d 'Threat Name')) (Get-Val $d 'Detection User') (Get-Val $d 'Path') '' }
        'Microsoft-Windows-Windows Defender/Operational|1117' { New-Alert $E 'INFO' 'Defender took action' (Get-Val $d 'Detection User') (Get-Val $d 'Threat Name') (Get-Val $d 'Action Name') }
        'Microsoft-Windows-Windows Defender/Operational|5001' { New-Alert $E 'HIGH' 'Defender real-time protection DISABLED' '' '' '' }
        { $_ -in 'Microsoft-Windows-Windows Defender/Operational|5010', 'Microsoft-Windows-Windows Defender/Operational|5012' } { New-Alert $E 'HIGH' 'Defender scanning DISABLED' '' '' '' }
        'Microsoft-Windows-Windows Defender/Operational|5013' { New-Alert $E 'MED' 'Tamper protection blocked a Defender change' '' (Get-Val $d 'Value') '' }
        'Microsoft-Windows-Windows Defender/Operational|5007' {
            $nv = Get-Val $d 'New Value'
            if ($nv -match '(?i)\\Exclusions\\') { New-Alert $E 'HIGH' 'Defender EXCLUSION added/changed' '' '' $nv }
            elseif ($nv -match '(?i)Disable(RealtimeMonitoring|BehaviorMonitoring|IOAVProtection|ScriptScanning|AntiSpyware|AntiVirus|OnAccessProtection)\s*=\s*0x1') { New-Alert $E 'HIGH' 'Defender protection setting turned OFF' '' '' $nv }
        }
        # --- PowerShell
        'Microsoft-Windows-PowerShell/Operational|4104' {
            $path = Get-Val $d 'Path'
            if ($path -and $PSScriptRoot -and $path.StartsWith($PSScriptRoot, [StringComparison]::OrdinalIgnoreCase)) { return }
            $text = Get-Val $d 'ScriptBlockText'
            $who2 = Resolve-SidName ([string]$E.UserId)
            if ($E.Level -eq 3) { New-Alert $E 'HIGH' 'PowerShell flagged a suspicious script block' $who2 $path $text }
            elseif ($text -match $script:PsRegex) { New-Alert $E 'HIGH' ('Suspicious PowerShell: {0}' -f $Matches[0]) $who2 $path $text }
        }
        # --- Sysmon
        'Microsoft-Windows-Sysmon/Operational|1' {
            $cmd = Get-Val $d 'CommandLine'
            $img = Split-Path -Leaf (Get-Val $d 'Image')
            if ($cmd -match $script:CmdHigh) { New-Alert $E 'HIGH' 'Suspicious command' (Get-Val $d 'User') $img $cmd }
            elseif ($cmd -match $script:CmdMed) { New-Alert $E 'MED' 'Recon / lateral-movement command' (Get-Val $d 'User') $img $cmd }
        }
        'Microsoft-Windows-Sysmon/Operational|3' {
            $img = Get-Val $d 'Image'
            $dst = Get-Val $d 'DestinationIp'
            if ($img -match $script:LolbinRegex -and $dst -notmatch '^(127\.|::1$|0:0:0:0:0:0:0:1)') {
                New-Alert $E 'MED' 'LOLBin made a network connection' (Get-Val $d 'User') (Split-Path -Leaf $img) ('-> {0}:{1} {2}' -f $dst, (Get-Val $d 'DestinationPort'), (Get-Val $d 'DestinationHostname'))
            }
        }
        'Microsoft-Windows-Sysmon/Operational|8' { New-Alert $E 'HIGH' 'Remote thread created (process injection?)' '' (Get-Val $d 'TargetImage') ('from ' + (Get-Val $d 'SourceImage')) }
        'Microsoft-Windows-Sysmon/Operational|10' {
            $src = Get-Val $d 'SourceImage'
            if ((Get-Val $d 'TargetImage') -match '(?i)\\lsass\.exe$' -and $src -notmatch $script:LsassSafe) {
                New-Alert $E 'HIGH' 'LSASS memory access (credential dumping?)' (Get-Val $d 'SourceUser') $src ('access ' + (Get-Val $d 'GrantedAccess'))
            }
        }
        # --- Task Scheduler / DNS
        'Microsoft-Windows-TaskScheduler/Operational|106' {
            $task = Get-Val $d 'TaskName'
            $sev = 'HIGH'
            if ($task -like '\Microsoft\*') { $sev = 'MED' }
            New-Alert $E $sev 'Scheduled task registered' (Get-Val $d 'UserContext') $task ''
        }
        { $_ -in 'DNS Server|770', 'DNS Server|150' } { New-Alert $E 'HIGH' 'DNS server plugin DLL (DnsAdmins attack!)' '' '' $E.Message }
    }
}

function Get-SprayAlerts([object[]]$Events) {
    if (-not $Events -or $Events.Count -eq 0) { return }
    $rows = foreach ($e in $Events) {
        $d = Get-Fields $e
        $src = Get-Val $d 'IpAddress'
        if (-not $src -or $src -eq '-') { $src = Get-Val $d 'WorkstationName' }
        if (-not $src) { $src = '(unknown)' }
        [pscustomobject]@{ Source = $src; User = (Get-Val $d 'TargetUserName'); Event = $e }
    }
    foreach ($g in ($rows | Group-Object Source)) {
        $users = @($g.Group | ForEach-Object { $_.User } | Select-Object -Unique)
        $first = $g.Group[0].Event
        $sample = ($users | Select-Object -First 8) -join ', '
        if ($users.Count -ge 5) {
            New-Alert $first 'HIGH' 'PASSWORD SPRAY' '' $g.Name ('{0} failed logons across {1} accounts: {2}' -f $g.Count, $users.Count, $sample)
        } elseif ($g.Count -ge $SprayThreshold) {
            New-Alert $first 'MED' 'Brute force / failed logon burst' '' $g.Name ('{0} failed logons for {1}' -f $g.Count, $sample)
        }
    }
}

# ---------------------------------------------------------------- output
function Write-Alert($A) {
    $color = 'Gray'
    if ($A.Severity -eq 'HIGH') { $color = 'Red' } elseif ($A.Severity -eq 'MED') { $color = 'Yellow' }
    $line = '{0:HH:mm:ss} [{1,-4}] {2}' -f $A.Time, $A.Severity, $A.Title
    if ($A.Target) { $line += ('  target: {0}' -f $A.Target) }
    if ($A.Who) { $line += ('  by: {0}' -f $A.Who) }
    Write-Host $line -ForegroundColor $color
    if ($A.Detail) { Write-Host ('           {0}' -f $A.Detail) -ForegroundColor $color }
}

function Show-Alerts($Alerts, [string]$CsvPath) {
    $all = @($Alerts | Sort-Object Time)
    if ($all.Count -eq 0) { return 0 }
    try { $all | Export-Csv -LiteralPath $CsvPath -Append -NoTypeInformation -Encoding UTF8 } catch { }
    $min = Get-SevRank $MinSeverity
    $shown = @($all | Where-Object { (Get-SevRank $_.Severity) -ge $min })
    if ($shown.Count -eq 0) { return $all.Count }
    Write-Host ''   # end the status line
    foreach ($g in ($shown | Group-Object -Property { '{0}|{1}|{2}' -f $_.Severity, $_.Title, $_.Who })) {
        $items = @($g.Group)
        if ($items.Count -gt 5) {
            foreach ($a in $items[0..2]) { Write-Alert $a }
            $color = 'Gray'
            if ($items[0].Severity -eq 'HIGH') { $color = 'Red' } elseif ($items[0].Severity -eq 'MED') { $color = 'Yellow' }
            Write-Host ('           ... +{0} more "{1}" (see CSV)' -f ($items.Count - 3), $items[0].Title) -ForegroundColor $color
        } else {
            foreach ($a in $items) { Write-Alert $a }
        }
    }
    if (-not $NoBeep -and @($shown | Where-Object { $_.Severity -eq 'HIGH' }).Count -gt 0) {
        try { [Console]::Beep(1200, 250); [Console]::Beep(900, 250) } catch { }
    }
    $all.Count
}

# ---------------------------------------------------------------- startup checks
function Test-AuditSetup([switch]$Fix) {
    $rows = @()
    try { $rows = @(& auditpol.exe /get /category:* /r | Where-Object { $_ -match ',' } | ConvertFrom-Csv) } catch { }
    if ($rows.Count -eq 0) { Write-Warn 'Could not read the audit policy (auditpol).' }
    else {
        $byGuid = @{}
        foreach ($r in $rows) { $byGuid[[string]$r.'Subcategory GUID'] = [string]$r.'Inclusion Setting' }
        foreach ($c in $script:AuditChecks) {
            $setting = [string]$byGuid[$c.Guid]
            if ($setting -match $c.Need) { Write-Good ('{0,-36} {1}' -f $c.Name, $setting); continue }
            $flag = '/success:enable'
            if ($c.Need -eq 'Failure') { $flag = '/failure:enable' }
            if ($Fix) {
                & auditpol.exe /set ('/subcategory:{0}' -f $c.Guid) $flag | Out-Null
                Write-Good ('{0,-36} turned on (events {1})' -f $c.Name, $c.Events)
            } else {
                Write-Warn ('{0,-36} OFF -> events {1} will never appear. Fix: auditpol /set /subcategory:"{2}" {3}' -f $c.Name, $c.Events, $c.Guid, $flag)
            }
        }
        if ($Fix) { Write-Warn 'If a GPO sets audit policy it can undo this at the next refresh (5 min on a DC) - set it in the GPO too.' }
    }

    $cmdKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    $cmdOn = (Get-ItemProperty -LiteralPath $cmdKey -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled -eq 1
    $sbKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $sbOn = (Get-ItemProperty -LiteralPath $sbKey -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging -eq 1
    if ($Fix) {
        if (-not (Test-Path -LiteralPath $cmdKey)) { New-Item -Path $cmdKey -Force | Out-Null }
        Set-ItemProperty -Path $cmdKey -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
        if (-not (Test-Path -LiteralPath $sbKey)) { New-Item -Path $sbKey -Force | Out-Null }
        Set-ItemProperty -Path $sbKey -Name EnableScriptBlockLogging -Value 1 -Type DWord
        $cmdOn = $true; $sbOn = $true
        Write-Good 'Command lines in 4688 and PowerShell script block logging turned on.'
    }
    if ($cmdOn) { Write-Good 'Command lines are recorded in 4688' } else { Write-Warn '4688 has no command lines -> suspicious-command detection is blind without Sysmon (use -EnableAuditing)' }
    if ($sbOn) { Write-Good 'PowerShell script block logging on' } else { Write-Warn 'Script block logging off -> only blocks Windows itself flags as suspicious are logged (use -EnableAuditing)' }
}

# ---------------------------------------------------------------- main
if ($MyInvocation.InvocationName -eq '.') { return }
if (-not (Test-IsAdmin)) { Write-Bad 'Run this from an elevated PowerShell (the Security log needs admin).'; exit 1 }

$reportDir = Join-Path $OutDir 'reports'
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
$csvPath = Join-Path $reportDir ('watch-events-{0}-{1}.csv' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd'))

Write-Section ('Event watcher on {0} - every {1}s' -f $env:COMPUTERNAME, $IntervalSeconds)
Test-AuditSetup -Fix:$EnableAuditing

$script:DomainDN = ''
try { $script:DomainDN = [string]([ADSI]'LDAP://RootDSE').defaultNamingContext } catch { }

$present = @{}
foreach ($l in @($script:LogSecurity, $script:LogSystem, $script:LogPowerShell, $script:LogDefender, $script:LogSysmon, $script:LogTasks, $script:LogDns)) {
    $info = Get-WinEvent -ListLog $l -ErrorAction SilentlyContinue
    if ($info -and $info.IsEnabled) { $present[$l] = $true }
}
$script:HasSysmon = $present.ContainsKey($script:LogSysmon)

$secIds = @(4720, 4722, 4724, 4726, 4728, 4732, 4756, 4741, 4740, 4697, 4698, 4702, 1102, 4719, 5136)
if (-not $script:HasSysmon) { $secIds += 4688 }   # with Sysmon, use Sysmon 1 instead (avoids duplicate alerts)
$sources = @(
    @{ Log = $script:LogSecurity; Queries = @(
        @{ Ids = $secIds },
        @{ Ids = @(4769); Data = " and EventData[Data[@Name='TicketEncryptionType']='0x17']" },
        @{ Ids = @(4768); Data = " and EventData[Data[@Name='PreAuthType']='0']" },
        @{ Ids = @(4662); Data = " and EventData[Data[@Name='AccessMask']='0x100']" },
        @{ Ids = @(4625); Aggregate = $true }) },
    @{ Log = $script:LogSystem; Queries = @(@{ Ids = @(7045, 104, 7036, 7040, 7031, 7034) }) },
    @{ Log = $script:LogPowerShell; Queries = @(@{ Ids = @(4104) }) },
    @{ Log = $script:LogDefender; Queries = @(@{ Ids = @(1116, 1117, 5001, 5007, 5010, 5012, 5013) }) },
    @{ Log = $script:LogSysmon; Queries = @(@{ Ids = @(1, 3, 8, 10) }) },
    @{ Log = $script:LogTasks; Queries = @(@{ Ids = @(106) }) },
    @{ Log = $script:LogDns; Queries = @(@{ Ids = @(770, 150) }) }
)
$sources = @($sources | Where-Object { $present.ContainsKey($_.Log) })

Write-Section 'Watching'
$script:Cursor = @{}
foreach ($s in $sources) {
    $script:Cursor[$s.Log] = Get-StartCursor -Log $s.Log -Minutes $LookbackMinutes
    Write-Info $s.Log
}
if (-not $script:HasSysmon) { Write-Info 'Sysmon not installed: LSASS access / injection / network detections are off (4688 used for commands).' }
if ($LookbackMinutes -gt 0) { Write-Info ('First pass includes the last {0} minutes.' -f $LookbackMinutes) }
Write-Info ('Alerts also go to {0}' -f $csvPath)
Write-Info 'Ctrl+C to stop.'

$total = 0
while ($true) {
    $alerts = New-Object System.Collections.Generic.List[object]
    $failed = New-Object System.Collections.Generic.List[object]
    foreach ($s in $sources) {
        $latest = Get-LatestRecordId $s.Log
        if ($null -eq $latest) { continue }
        $after = [int64]$script:Cursor[$s.Log]
        if ($latest -lt $after) {
            $alerts.Add((New-PlainAlert 'HIGH' ('{0} log record numbers went backwards (log cleared?)' -f $s.Log) ''))
            $after = 0
        }
        if ($latest -gt $after) {
            foreach ($q in $s.Queries) {
                $events = Read-Window -Log $s.Log -Ids $q.Ids -After $after -UpTo $latest -SysFilter $q.Sys -DataFilter $q.Data
                foreach ($e in $events) {
                    if ($q.Aggregate) { $failed.Add($e); continue }
                    foreach ($a in @(Convert-Event $e)) { if ($a) { $alerts.Add($a) } }
                }
            }
        }
        $script:Cursor[$s.Log] = $latest
    }
    foreach ($a in @(Get-SprayAlerts $failed.ToArray())) { if ($a) { $alerts.Add($a) } }
    $total += Show-Alerts -Alerts $alerts.ToArray() -CsvPath $csvPath
    Write-Host ("`r[*] last check {0:HH:mm:ss} - {1} alerts so far   " -f (Get-Date), $total) -NoNewline -ForegroundColor DarkGray
    Start-Sleep -Seconds $IntervalSeconds
}
