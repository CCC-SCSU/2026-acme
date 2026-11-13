#Requires -RunAsAdministrator
<#
  enable_dc_logging.ps1 - run on the domain controller. Turns on every log the CCDC Hunts Splunk app
  needs, then checks that the Splunk forwarder is collecting them.

    powershell -ExecutionPolicy Bypass -File .\enable_dc_logging.ps1          turn everything on, then show the result
    powershell -ExecutionPolicy Bypass -File .\enable_dc_logging.ps1 -Check   only show what's on and off (changes nothing)

  Run -Check again 10 minutes later: if Group Policy manages auditing on this DC, it can switch things back.

  Sysmon: if it isn't installed, put Sysmon64.exe and your Sysmon config (a .xml with "sysmon" in its name)
  in the same folder as this script and it installs it.

  Undo the audit policy part:  auditpol /restore /file:C:\ccdc\auditpol_backup_<time>.csv
#>
[CmdletBinding()]
param([switch]$Check)

$ErrorActionPreference = 'Continue'
Import-Module ActiveDirectory
Add-Type -AssemblyName System.DirectoryServices
New-Item -ItemType Directory -Path C:\ccdc -Force | Out-Null
$Stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$UF    = 'C:\Program Files\SplunkUniversalForwarder'
$Fix   = -not $Check

function Title($t) { Write-Host "`n== $t ==" -ForegroundColor Cyan }
function On($t)    { Write-Host "   [on ] $t" -ForegroundColor Green }
function Off($t)   { Write-Host "   [OFF] $t" -ForegroundColor Red }
function Info($t)  { Write-Host "         $t" -ForegroundColor Gray }
function Warn($t)  { Write-Host "   !  $t" -ForegroundColor Yellow }

if ($Check) { Write-Host 'CHECK ONLY: nothing will be changed.' -ForegroundColor Yellow }

# ===================================================================== 1. audit policy
# Windows only writes most Security log events if its audit policy says so. Each line is one audit
# subcategory (by GUID, so it works on any language of Windows), whether to log successes and/or
# failures, and what in the Splunk app uses it. This only turns logging ON, never off.
$audit = @(
    @{ Code = '923F'; Name = 'Credential Validation';            S = 1; F = 1; Why = 'NTLM logins (4776)' }
    @{ Code = '9242'; Name = 'Kerberos Authentication Service';  S = 1; F = 1; Why = 'Kerberos logins, AS-REP roasting (4768, 4771)' }
    @{ Code = '9240'; Name = 'Kerberos Service Ticket Operations'; S = 1; F = 1; Why = 'Kerberoasting alert (4769)' }
    @{ Code = '9235'; Name = 'User Account Management';          S = 1; F = 1; Why = 'New account, Account locked out, account changes (4720, 4740, 4738)' }
    @{ Code = '9236'; Name = 'Computer Account Management';      S = 1; F = 0; Why = 'computers added to the domain (4741)' }
    @{ Code = '9237'; Name = 'Security Group Management';        S = 1; F = 0; Why = 'Account added to an admin group (4728, 4732, 4756)' }
    @{ Code = '923A'; Name = 'Other Account Management Events';  S = 1; F = 0; Why = 'password hash read (4782)' }
    @{ Code = '922B'; Name = 'Process Creation';                 S = 1; F = 0; Why = 'whoami alert, backup for Sysmon (4688)' }
    @{ Code = '923B'; Name = 'Directory Service Access';         S = 1; F = 1; Why = 'DCSync alert (4662)' }
    @{ Code = '923C'; Name = 'Directory Service Changes';        S = 1; F = 0; Why = 'AD object and GPO changes (5136)' }
    @{ Code = '9215'; Name = 'Logon';                            S = 1; F = 1; Why = 'logons, Password spraying (4624, 4625)' }
    @{ Code = '9217'; Name = 'Account Lockout';                  S = 0; F = 1; Why = 'logons to locked accounts (4625)' }
    @{ Code = '921B'; Name = 'Special Logon';                    S = 1; F = 0; Why = 'admin logons (4672)' }
    @{ Code = '921C'; Name = 'Other Logon/Logoff Events';        S = 1; F = 1; Why = 'RDP reconnects (4778, 4779)' }
    @{ Code = '9227'; Name = 'Other Object Access Events';       S = 1; F = 1; Why = 'Scheduled task created (4698)' }
    @{ Code = '9221'; Name = 'Certification Services';           S = 1; F = 1; Why = 'certificate requests, if AD CS is installed (4886-4888)' }
    @{ Code = '922F'; Name = 'Audit Policy Change';              S = 1; F = 1; Why = 'someone turning auditing off (4719)' }
    @{ Code = '9230'; Name = 'Authentication Policy Change';     S = 1; F = 0; Why = 'trust and Kerberos policy changes (4706, 4713)' }
    @{ Code = '9232'; Name = 'MPSSVC Rule-Level Policy Change';  S = 1; F = 0; Why = 'Windows Firewall rules added or changed (4946-4950)' }
    @{ Code = '9210'; Name = 'Security State Change';            S = 1; F = 0; Why = 'system time changed (4616), breaks Kerberos' }
    @{ Code = '9211'; Name = 'Security System Extension';        S = 1; F = 0; Why = 'service installed (4697), backup for 7045' }
    @{ Code = '9212'; Name = 'System Integrity';                 S = 1; F = 1; Why = 'audit events lost (4612)' }
)

function Get-AuditSetting([string]$guid) {
    $rows = & auditpol.exe /get "/subcategory:$guid" /r | Where-Object { $_ } | ConvertFrom-Csv
    return "$(@($rows)[0].'Inclusion Setting')"
}

Title 'Audit policy (what the Security log records)'
if ($Fix) {
    & auditpol.exe /backup "/file:C:\ccdc\auditpol_backup_$Stamp.csv" | Out-Null
    Info "Backed up the current audit policy to C:\ccdc\auditpol_backup_$Stamp.csv"
    # Make these detailed settings win over the old-style category settings
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -Value 1 -PropertyType DWord -Force | Out-Null
}
foreach ($a in $audit) {
    $guid = "{0CCE$($a.Code)-69AE-11D9-BED3-505054503030}"
    if ($Fix) {
        $flags = @()
        if ($a.S) { $flags += '/success:enable' }
        if ($a.F) { $flags += '/failure:enable' }
        & auditpol.exe /set "/subcategory:$guid" @flags | Out-Null
    }
    $now = Get-AuditSetting $guid
    $good = (-not $a.S -or $now -match 'Success') -and (-not $a.F -or $now -match 'Failure')
    $line = '{0,-36} {1,-22} {2}' -f $a.Name, $now, $a.Why
    if ($good) { On $line } else { Off $line }
}

# ===================================================================== 2. command lines and PowerShell
Title 'Command lines and PowerShell'
function Set-Dword([string]$path, [string]$name, [int]$value) {
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    New-ItemProperty -Path $path -Name $name -Value $value -PropertyType DWord -Force | Out-Null
}
function Test-Dword([string]$path, [string]$name, [int]$value) {
    try { return ((Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name -eq $value) } catch { return $false }
}
$regs = @(
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name = 'ProcessCreationIncludeCmdLine_Enabled'
       Why = 'Process creation events (4688) include the full command line' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'EnableScriptBlockLogging'
       Why = 'PowerShell logs every script it runs (4104): Suspicious PowerShell alert' }
)
foreach ($r in $regs) {
    if ($Fix) { Set-Dword $r.Path $r.Name 1 }
    if (Test-Dword $r.Path $r.Name 1) { On $r.Why } else { Off $r.Why }
}
$v2 = Get-WindowsFeature PowerShell-V2 -ErrorAction SilentlyContinue
if ($v2 -and $v2.Installed) {
    Warn 'PowerShell 2.0 is installed. Attackers run "powershell -version 2" to skip script logging.'
    Info 'Remove it (no reboot needed): Uninstall-WindowsFeature PowerShell-V2'
}

# ===================================================================== 3. DCSync detection
# The DCSync alert looks for event 4662 on the domain object. Windows only writes it if the domain
# object's audit list (its SACL) says to record anyone using the three "replicate directory" rights.
Title 'DCSync detection (audit entries on the domain object)'
$dn   = (Get-ADDomain).DistinguishedName
$sid  = New-Object System.Security.Principal.SecurityIdentifier 'S-1-1-0'     # Everyone
$repl = @{ '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'Replicating Directory Changes'
           '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'Replicating Directory Changes All'
           '89e95b76-444d-4c62-991a-0facbeda640c' = 'Replicating Directory Changes In Filtered Set' }
function Get-ReplAudited {
    $acl = Get-Acl -Path "AD:\$dn" -Audit
    @($acl.GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | Where-Object {
        $_.IdentityReference.Value -eq 'S-1-1-0' -and
        (([int]$_.AuditFlags -band 1) -ne 0) -and (([int]$_.ActiveDirectoryRights -band 256) -ne 0)
    } | ForEach-Object { $_.ObjectType.ToString() })
}
$audited = Get-ReplAudited
$missing = @($repl.Keys | Where-Object { $audited -notcontains $_ -and $audited -notcontains '00000000-0000-0000-0000-000000000000' })
if ($Fix -and $missing.Count) {
    $acl = Get-Acl -Path "AD:\$dn" -Audit
    foreach ($g in $missing) {
        $rule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($sid,
                    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                    [System.Security.AccessControl.AuditFlags]::Success, [guid]$g)
        $acl.AddAuditRule($rule)
    }
    Set-Acl -Path "AD:\$dn" -AclObject $acl
    $audited = Get-ReplAudited
}
foreach ($g in $repl.Keys) {
    if ($audited -contains $g -or $audited -contains '00000000-0000-0000-0000-000000000000') { On "Auditing '$($repl[$g])' on $dn" }
    else { Off "Auditing '$($repl[$g])' on $dn" }
}

# ===================================================================== 4. Sysmon
Title 'Sysmon (most of the Windows alerts need it)'
$sysmon = Get-Service Sysmon64, Sysmon -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $sysmon -and $Fix) {
    $exe = Join-Path $PSScriptRoot 'Sysmon64.exe'
    $xml = Get-ChildItem -Path $PSScriptRoot -Filter '*.xml' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'sysmon' } | Select-Object -First 1
    if ((Test-Path $exe) -and $xml) {
        & $exe -accepteula -i $xml.FullName | Out-Null
        $sysmon = Get-Service Sysmon64 -ErrorAction SilentlyContinue
    }
}
if (-not $sysmon) {
    Off 'Sysmon is not installed. Put Sysmon64.exe and a Sysmon config .xml next to this script and run it again.'
} else {
    if ($Fix -and $sysmon.Status -ne 'Running') { Start-Service $sysmon.Name; $sysmon.Refresh() }
    if ($sysmon.Status -eq 'Running') { On "$($sysmon.Name) is running" } else { Off "$($sysmon.Name) is $($sysmon.Status)" }
    $bin = Join-Path $env:windir "$($sysmon.Name).exe"
    if (Test-Path $bin) {
        $conf = (& $bin -c | Out-String)
        $types = [ordered]@{ ProcessCreate = 'event 1: smbexec, remote shells, whoami, disguised scripts'
                             NetworkConnect = 'event 3: PowerShell connections'
                             FileCreate = 'event 11: .bat in Windows\Temp, dropped files'
                             RegistryEvent = 'events 12-14: Autorun / IFEO alert'
                             WmiEvent = 'events 19-21: WMI subscription alert' }
        foreach ($t in $types.Keys) {
            if ($conf -match "\b$t\b") { On "config has $t rules ($($types[$t]))" } else { Off "config has no $t rules ($($types[$t]))" }
        }
    }
}

# ===================================================================== 5. event logs: on, and big enough
# Bigger logs mean a flood of events (or a slow forwarder) doesn't push out what you need to look at.
Title 'Event logs (switched on, and large enough to hold a busy day)'
$logs = @(
    @{ Name = 'Security';                                        MB = 1024 }
    @{ Name = 'System';                                          MB = 256 }
    @{ Name = 'Application';                                     MB = 128 }
    @{ Name = 'Microsoft-Windows-PowerShell/Operational';        MB = 256 }
    @{ Name = 'Microsoft-Windows-WinRM/Operational';             MB = 64 }
    @{ Name = 'Microsoft-Windows-Windows Defender/Operational';  MB = 64 }
    @{ Name = 'Microsoft-Windows-Sysmon/Operational';            MB = 512 }
    @{ Name = 'Microsoft-Windows-DNSServer/Audit';               MB = 64 }
)
foreach ($l in $logs) {
    $cfg = Get-WinEvent -ListLog $l.Name -ErrorAction SilentlyContinue
    if (-not $cfg) { Off "$($l.Name): doesn't exist on this box"; continue }
    if ($Fix) {
        $want = [int64]$l.MB * 1MB
        $changed = $false
        if (-not $cfg.IsEnabled) { $cfg.IsEnabled = $true; $changed = $true }
        if ($cfg.MaximumSizeInBytes -lt $want) { $cfg.MaximumSizeInBytes = $want; $changed = $true }
        if ($changed) { try { $cfg.SaveChanges() } catch { Warn "$($l.Name): $($_.Exception.Message)" } }
        $cfg = Get-WinEvent -ListLog $l.Name
    }
    $text = '{0,-50} {1,6} MB' -f $l.Name, [math]::Round($cfg.MaximumSizeInBytes / 1MB)
    if ($cfg.IsEnabled) { On $text } else { Off $text }
}

# ===================================================================== 6. Splunk forwarder
Title 'Splunk forwarder (is it sending these logs?)'
$need = [ordered]@{
    'WinEventLog://Security'                                       = 'false'
    'WinEventLog://System'                                         = 'false'
    'WinEventLog://Application'                                    = 'false'
    'WinEventLog://Microsoft-Windows-PowerShell/Operational'       = 'false'
    'WinEventLog://Microsoft-Windows-WinRM/Operational'            = 'false'
    'WinEventLog://Microsoft-Windows-Windows Defender/Operational' = 'false'
    'WinEventLog://Microsoft-Windows-Sysmon/Operational'           = 'true'
    'WinEventLog://Microsoft-Windows-DNSServer/Audit'              = 'false'
}
if (-not (Test-Path "$UF\bin\splunk.exe")) {
    Off "Splunk Universal Forwarder not found at $UF"
} else {
    $svc = Get-CimInstance Win32_Service -Filter "Name='SplunkForwarder'"
    if ($svc.StartName -ne 'LocalSystem') { Warn "The forwarder runs as '$($svc.StartName)'. It needs LocalSystem to read the Security log on a DC." }

    function Get-ActiveInputs {
        $active = @{}
        $stanza = $null
        foreach ($line in (& "$UF\bin\splunk.exe" btool inputs list 2>$null)) {
            if ($line -match '^\[(.+)\]\s*$') { $stanza = $Matches[1]; $active[$stanza] = $true }
            elseif ($stanza -and $line -match '^\s*disabled\s*=\s*(1|true)\s*$') { $active[$stanza] = $false }
        }
        return $active
    }
    $active = Get-ActiveInputs
    $add = @($need.Keys | Where-Object { -not $active.ContainsKey($_) })
    if ($Fix -and $add.Count) {
        $dir = "$UF\etc\apps\ccdc_inputs\local"
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $text = ($add | ForEach-Object { "`r`n[$_]`r`ndisabled = 0`r`nrenderXml = $($need[$_])`r`n" }) -join ''
        Add-Content -Path "$dir\inputs.conf" -Value $text -Encoding ASCII
        Info "Added $($add.Count) input(s) to $dir\inputs.conf. Restarting the forwarder..."
        Restart-Service SplunkForwarder
        $active = Get-ActiveInputs
    }
    foreach ($k in $need.Keys) {
        if (-not $active.ContainsKey($k)) { Off "$k is not collected" }
        elseif (-not $active[$k]) { Off "$k is set to disabled = 1. Find where: & '$UF\bin\splunk.exe' btool inputs list '$k' --debug" }
        else { On $k }
    }
    if ((Get-Service SplunkForwarder).Status -eq 'Running') { On 'SplunkForwarder service is running' } else { Off 'SplunkForwarder service is not running' }
}

# ===================================================================== 7. will Group Policy undo this?
Title 'Group Policy'
$gpAudit = "$env:windir\security\audit\audit.csv"
if ((Test-Path $gpAudit) -and @(Get-Content $gpAudit | Where-Object { $_ }).Count -gt 1) {
    Warn 'A Group Policy sets audit policy on this DC. It re-applies about every 5 minutes and can undo section 1.'
    Info 'Run this script with -Check in 10 minutes. If anything flipped back, set it in that GPO instead.'
} else {
    Info 'No Group Policy audit settings found, so these local settings should stick.'
    Info 'A red-team GPO could still change them later: re-run with -Check now and then.'
}

Title 'Next'
Info 'This adds Security log volume (process creation and directory access especially). Watch the license panel on'
Info 'the Health & Splunk dashboard. If you go over, filter noise on the forwarder (blacklist3 in inputs.conf), never'
Info 'event IDs the alerts use: 4624 4625 4662 4688 4698 4720 4728 4732 4738 4740 4756 4768 4769 4776.'