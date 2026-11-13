#Requires -RunAsAdministrator
<#
quick: 
----
.\dc_firewall.ps1 to run
netsh advfirewall import C:\ccdc\fw_original.wfw to backup if you messed up scoring
Disable-NetFirewallRule -Group 'CCDC DC Egress' if u need to download stuff
----

  dc_firewall.ps1 - Windows Firewall for the domain controller.

  What it does
    - Scored services (DNS, WinRM) stay open to everyone.
    - Kerberos, LDAP, Global Catalog and time stay open to internal boxes only.
    - SMB (445) and RPC (135 + dynamic ports) are open to domain members only. NetExec's smbexec and
      atexec need SMB, wmiexec needs RPC, and secretsdump/DCSync, BloodHound and Kerberoasting need
      RPC, LDAP or Kerberos, so none of those work against the DC from outside any more.
    - Everything else inbound is blocked. Every other inbound allow rule (including any the red team
      added) is disabled, not deleted.
    - Outbound: the DC can't send SMB to non-internal addresses (stops coerced logins being relayed),
      and PowerShell, wscript, cscript, mshta, certutil, bitsadmin, curl and friends can't reach
      non-internal addresses (stops payload downloads and beacons). Everything else outbound still works.

  How to run (admin PowerShell, in the folder with this file)
    1. Fill in SETTINGS below.
    2. Preview, changes nothing:   powershell -ExecutionPolicy Bypass -File .\dc_firewall.ps1 -DryRun
    3. Apply:                      powershell -ExecutionPolicy Bypass -File .\dc_firewall.ps1
       It backs up the current firewall first. Add -Force to skip the "type YES" question.
       Then test from another box (list at the bottom of this file).

  Undo
    Last run:                      .\dc_firewall.ps1 -Undo
    Back to before the first run:  netsh advfirewall import C:\ccdc\fw_original.wfw
    Let PowerShell/curl download for a bit:   Disable-NetFirewallRule -Group 'CCDC DC Egress'
    Put that block back:                      Enable-NetFirewallRule -Group 'CCDC DC Egress'
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Undo,
    [switch]$Force                # skip the "type YES" question
)

# ================================ SETTINGS ================================
# Scored on the DC, open to everyone. If the scoring list says the DC is also checked on another
# port (LDAP 389, for example), add it here.
$OpenToAnyTcp  = @(53, 5985, 5986)     # DNS, WinRM over HTTP and HTTPS
$OpenToAnyUdp  = @(53)                 # DNS
$AllowPing     = $true

# Other internal subnets with boxes that use AD, DNS or time from the DC: the mail server (AD logins),
# e-commerce, Splunk, workstations. The DC's own subnet is added automatically.
# Example: @('172.20.242.0/24')
$InternalNets  = @()

# Windows boxes joined to the domain (MSSQL, Windows 11). Only these get SMB and RPC.
# Leave empty to read them from Active Directory; you'll see the list before anything changes.
$DomainMembers = @()

# IPs allowed to RDP to the DC. Empty = RDP closed (use the VM console).
$AdminIPs      = @()

# Outbound blocks to anything that isn't internal (see "What it does").
$BlockSmbEgress    = $true
$BlockScriptEgress = $true
# ==========================================================================

$ErrorActionPreference = 'Stop'
$Dir         = 'C:\ccdc'
$Group       = 'CCDC DC Firewall'
$EgressGroup = 'CCDC DC Egress'
$Stamp       = Get-Date -Format 'yyyyMMdd_HHmmss'
New-Item -ItemType Directory -Path $Dir -Force | Out-Null

function Say($msg, $color = 'Gray') { Write-Host $msg -ForegroundColor $color }
function Warn($msg) { Write-Host "  ! $msg" -ForegroundColor Yellow }

# ------------------------------------------------------------------ undo
if ($Undo) {
    $last = Get-ChildItem "$Dir\fw_backup_*.wfw" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $last) { throw "No backup found in $Dir." }
    & netsh advfirewall import "$($last.FullName)" | Out-Null
    Say "Restored the firewall from $($last.Name)." Green
    return
}

# ------------------------------------------------------------------ IPv4 helpers
function ConvertTo-Int64IP([string]$ip) {
    $b = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
    return [int64]$b[0] * 16777216 + [int64]$b[1] * 65536 + [int64]$b[2] * 256 + [int64]$b[3]
}

function ConvertTo-IPString([int64]$n) {
    $a = [math]::Floor($n / 16777216)
    $b = [math]::Floor($n / 65536) % 256
    $c = [math]::Floor($n / 256) % 256
    $d = $n % 256
    return "$a.$b.$c.$d"
}

# "10.0.0.5", "10.0.0.0/24" or "10.0.0.5-10.0.0.9" -> object with Start and End as numbers
function Get-IPv4Range([string]$spec) {
    $spec = $spec.Trim()
    if ($spec -match '^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})$') {
        $first = $Matches[1]; $last = $Matches[2]
        return [pscustomobject]@{ Start = (ConvertTo-Int64IP $first); End = (ConvertTo-Int64IP $last) }
    }
    if ($spec -match '^(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?$') {
        $addr = $Matches[1]
        $len = 32
        if ($Matches[2]) { $len = [int]$Matches[2] }
        if ($len -gt 32) { throw "Bad prefix length in '$spec'" }
        $size  = [int64][math]::Pow(2, 32 - $len)
        $start = [int64]([math]::Floor((ConvertTo-Int64IP $addr) / $size) * $size)
        return [pscustomobject]@{ Start = $start; End = $start + $size - 1 }
    }
    throw "Not an IPv4 address, subnet or range: '$spec'. Fix it in SETTINGS."
}

# Sorted, overlap-free ranges
function Merge-Ranges([string[]]$Specs) {
    $sorted = @($Specs | Where-Object { $_ } | ForEach-Object { Get-IPv4Range $_ } | Sort-Object Start)
    $merged = New-Object System.Collections.Generic.List[object]
    foreach ($r in $sorted) {
        $prev = $null
        if ($merged.Count -gt 0) { $prev = $merged[$merged.Count - 1] }
        if ($prev -and $r.Start -le $prev.End + 1) {
            if ($r.End -gt $prev.End) { $prev.End = $r.End }
        } else {
            $merged.Add([pscustomobject]@{ Start = $r.Start; End = $r.End })
        }
    }
    return $merged
}

function Format-Range($r) {
    if ($r.Start -eq $r.End) { return (ConvertTo-IPString $r.Start) }
    return "$(ConvertTo-IPString $r.Start)-$(ConvertTo-IPString $r.End)"
}

function ConvertTo-FirewallList([string[]]$Specs) {
    foreach ($r in @(Merge-Ranges $Specs)) { Format-Range $r }
}

# Every IPv4 address NOT in $Specs, as firewall ranges (block rules can't say "except")
function Get-Complement([string[]]$Specs) {
    [int64]$next = 0
    foreach ($r in @(Merge-Ranges $Specs)) {
        if ($r.Start -gt $next) { Format-Range ([pscustomobject]@{ Start = $next; End = $r.Start - 1 }) }
        $next = $r.End + 1
    }
    if ($next -le 4294967295) { Format-Range ([pscustomobject]@{ Start = $next; End = [int64]4294967295 }) }
}

function Test-InRanges([string]$ip, $Ranges) {
    $ip = $ip -replace '^::ffff:', ''
    if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $false }
    $n = ConvertTo-Int64IP $ip
    foreach ($r in $Ranges) { if ($n -ge $r.Start -and $n -le $r.End) { return $true } }
    return $false
}

# ------------------------------------------------------------------ who's who
Say "`nCCDC domain controller firewall$(if ($DryRun) { '  (DRY RUN: nothing will change)' })" Cyan

$ownAddrs = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' })
$ownIPs   = @($ownAddrs | ForEach-Object { $_.IPAddress })
$ownNets  = @($ownAddrs | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" })
Say "  This DC: $($ownNets -join ', ')"

if ($DomainMembers.Count -eq 0) {
    Say "`nDomain members (read from Active Directory). Check every one is a real box:" Cyan
    try {
        Import-Module ActiveDirectory
        $computers = @(Get-ADComputer -Filter 'Enabled -eq $true' -Properties IPv4Address, OperatingSystem, whenCreated |
                       Where-Object { $_.Name -ne $env:COMPUTERNAME })
        foreach ($c in $computers) {
            $flag = ''
            if ($c.whenCreated -gt (Get-Date).AddHours(-24)) { $flag = '   <-- created in the last 24 hours. Red team?' }
            if ($c.IPv4Address) {
                $DomainMembers += $c.IPv4Address
                Say ("    {0,-18} {1,-16} {2}{3}" -f $c.Name, $c.IPv4Address, $c.OperatingSystem, $flag)
            } else {
                Warn "$($c.Name) has no DNS record, so it can't be allowed. If it's real, add its IP to `$DomainMembers."
            }
        }
    } catch {
        Warn "Couldn't read computers from AD ($($_.Exception.Message)). Fill in `$DomainMembers by hand."
    }
}

# Validate everything (throws on a typo) and build the address lists
$internalSpecs  = @($ownNets) + @($InternalNets) + @($DomainMembers)
$InternalList   = @(ConvertTo-FirewallList $internalSpecs)
$MemberList     = @(ConvertTo-FirewallList $DomainMembers)
$AdminList      = @(ConvertTo-FirewallList $AdminIPs)
$ExternalList   = @(Get-Complement $internalSpecs)
$InternalRanges = @(Merge-Ranges $internalSpecs)
$MemberRanges   = @(Merge-Ranges $DomainMembers)
$AdminRanges    = @(Merge-Ranges $AdminIPs)

$adPortsTcp     = @(88, 389, 464, 636, 3268, 3269)   # Kerberos, LDAP, kpasswd, LDAPS, Global Catalog
$adPortsUdp     = @(88, 123, 389, 464)               # Kerberos, time, LDAP ping, kpasswd
$memberPortsTcp = @(445, 135, 9389)                  # SMB, RPC endpoint mapper, AD Web Services

$sys = "$env:SystemRoot\System32"
$wow = "$env:SystemRoot\SysWOW64"
$EgressPrograms = foreach ($d in $sys, $wow) {
    "$d\WindowsPowerShell\v1.0\powershell.exe", "$d\WindowsPowerShell\v1.0\powershell_ise.exe",
    "$d\wscript.exe", "$d\cscript.exe", "$d\mshta.exe", "$d\certutil.exe", "$d\bitsadmin.exe",
    "$d\regsvr32.exe", "$d\rundll32.exe", "$d\curl.exe"
}
$EgressPrograms += "$env:ProgramFiles\PowerShell\7\pwsh.exe"

$isDhcp = [bool](Get-Service DHCPServer -ErrorAction SilentlyContinue)

# ------------------------------------------------------------------ plan
Say "`nAfter this runs, inbound:" Cyan
$ping = ''
if ($AllowPing) { $ping = ', ping' }
Say "  From anyone:          TCP $($OpenToAnyTcp -join ', ')  UDP $($OpenToAnyUdp -join ', ')$ping"
Say "  From internal:        Kerberos, LDAP, Global Catalog, time   [$($InternalList -join ', ')]"
if ($MemberList.Count) {
    Say "  From domain members:  SMB 445, RPC 135 + dynamic, AD Web Services 9389   [$($MemberList -join ', ')]"
} else {
    Warn "No domain members: SMB and RPC will be closed to everyone. Member servers lose Group Policy and some logins. Fill in `$DomainMembers."
}
if ($AdminList.Count) { Say "  RDP from:             $($AdminList -join ', ')" } else { Say "  RDP:                  closed" }
if ($isDhcp) { Say "  DHCP server:          UDP 67 from anyone (DHCP is installed here)" }
Say "  Everything else:      blocked"
if ($BlockSmbEgress)    { Say "Outbound: SMB to non-internal addresses blocked." }
if ($BlockScriptEgress) { Say "Outbound: PowerShell, script hosts, certutil, bitsadmin, curl etc. blocked to non-internal addresses." }

if (Get-Service CertSvc -ErrorAction SilentlyContinue) {
    Say "  AD CS is installed. Members can still enroll (RPC). Web enrollment on 80/443 stays closed, which also stops ESC8 relaying."
}
if (Get-Service W3SVC -ErrorAction SilentlyContinue) {
    Warn "IIS is installed on the DC. 80/443 stay closed. If something scored runs on it, add the port to `$OpenToAnyTcp."
}

# ------------------------------------------------------------------ pre-flight
function Get-Audience([int]$port) {
    if ($OpenToAnyTcp -contains $port)   { return 'anyone' }
    if ($adPortsTcp -contains $port)     { return 'internal' }
    if ($memberPortsTcp -contains $port) { return 'members' }
    if ($port -ge 49152)                 { return 'members' }   # dynamic RPC, roughly
    if ($port -eq 3389 -and $AdminList.Count) { return 'admins' }
    return 'nobody'
}
function Test-Allowed([string]$ip, [string]$audience) {
    switch ($audience) {
        'anyone'   { return $true }
        'internal' { return (Test-InRanges $ip $InternalRanges) }
        'members'  { return (Test-InRanges $ip $MemberRanges) }
        'admins'   { return (Test-InRanges $ip $AdminRanges) }
        default    { return $false }
    }
}

$procs = @{}
Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
$listen      = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -notin @('127.0.0.1', '::1') })
$listenPorts = @($listen | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object)

Say "`nListening TCP ports, and who can reach them after this runs:" Cyan
foreach ($p in $listenPorts) {
    $owner = ($listen | Where-Object { $_.LocalPort -eq $p } | Select-Object -First 1).OwningProcess
    $aud = Get-Audience $p
    if ($p -ge 49152) { $aud = 'members if it is an RPC port, otherwise nobody' }
    Say ("  {0,5}  {1,-16} {2}" -f $p, $procs[[int]$owner], $aud)
}

$cut = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {
    ($listenPorts -contains $_.LocalPort) -and
    ($_.RemoteAddress -notin @('127.0.0.1', '::1')) -and
    ($ownIPs -notcontains $_.RemoteAddress) -and
    -not (Test-Allowed $_.RemoteAddress (Get-Audience $_.LocalPort))
})
Say "`nLive connections into this DC that the new rules would cut off:" Cyan
if ($cut.Count) {
    $cut | Sort-Object RemoteAddress, LocalPort | ForEach-Object {
        Say ("    {0,-40} -> port {1,-5} ({2})" -f $_.RemoteAddress, $_.LocalPort, $procs[[int]$_.OwningProcess]) Yellow
    }
    Warn "If any of those is one of your boxes or the scorer, add it to SETTINGS before applying."
} else {
    Say "  None." Green
}

try {
    $gpoRules = @(Get-NetFirewallRule -PolicyStore RSOP -ErrorAction Stop | Where-Object { $_.Enabled -eq 'True' })
    if ($gpoRules.Count) {
        Warn "$($gpoRules.Count) firewall rule(s) come from Group Policy. This script can't touch them and they still apply:"
        $gpoRules | ForEach-Object { Say ("      {0} {1}  {2}" -f $_.Direction, $_.Action, $_.DisplayName) Yellow }
    }
} catch { }
try {
    if (@(Get-NetFirewallProfile -PolicyStore RSOP -ErrorAction Stop | Where-Object { $_.AllowLocalFirewallRules -eq 'False' }).Count) {
        Warn "Group Policy tells Windows to IGNORE local firewall rules. Fix that GPO first, or this script has no effect."
    }
} catch { }

# ------------------------------------------------------------------ rules
function Add-Rule {
    param([string]$Name, [string]$Direction = 'Inbound', [string]$Action = 'Allow', [string]$Protocol,
          [string[]]$Port, [string[]]$Remote = @('Any'), [string]$Program, [string]$IcmpType,
          [string]$RuleGroup = $Group, [string[]]$FallbackPort)
    $p = @{ DisplayName = "CCDC $Name"; Group = $RuleGroup; Direction = $Direction; Action = $Action
            Profile = 'Any'; Enabled = 'True'; RemoteAddress = $Remote }
    if ($Protocol) { $p.Protocol = $Protocol }
    if ($Port) {
        if ($Direction -eq 'Inbound') { $p.LocalPort = $Port } else { $p.RemotePort = $Port }
    }
    if ($Program)  { $p.Program = $Program }
    if ($IcmpType) { $p.IcmpType = $IcmpType }

    $what = $Protocol
    if ($Port) { $what = "$Protocol $($Port -join ',')" } elseif ($Program) { $what = $Program -replace [regex]::Escape($env:SystemRoot), '' }
    $where = $Remote -join ', '
    if ($Remote.Count -gt 3) { $where = "$($Remote[0..2] -join ', ') (+$($Remote.Count - 3) more)" }
    $dirWord = 'to'
    if ($Direction -eq 'Inbound') { $dirWord = 'from' }
    Say ("  {0,-8} {1,-5} {2,-44} {3} {4}" -f $Direction, $Action, $what, $dirWord, $where)
    if ($DryRun) { return }

    try {
        New-NetFirewallRule @p | Out-Null
    } catch {
        if (-not $FallbackPort) { throw }
        $p.LocalPort = $FallbackPort
        New-NetFirewallRule @p | Out-Null
        Warn "Used port $($FallbackPort -join ',') instead of $($Port -join ',') for '$Name'."
    }
}

function Add-AllRules {
    Add-Rule 'Scored TCP' -Protocol TCP -Port $OpenToAnyTcp
    Add-Rule 'Scored UDP' -Protocol UDP -Port $OpenToAnyUdp
    if ($AllowPing) { Add-Rule 'Ping' -Protocol ICMPv4 -IcmpType 8 }
    Add-Rule 'AD from internal (TCP)' -Protocol TCP -Port $adPortsTcp -Remote $InternalList
    Add-Rule 'AD from internal (UDP)' -Protocol UDP -Port $adPortsUdp -Remote $InternalList
    if ($MemberList.Count) {
        Add-Rule 'SMB from domain members' -Protocol TCP -Port 445 -Remote $MemberList
        Add-Rule 'RPC endpoint mapper from domain members' -Protocol TCP -Port RPCEPMap -Remote $MemberList -FallbackPort 135
        Add-Rule 'RPC dynamic from domain members' -Protocol TCP -Port RPC -Remote $MemberList -FallbackPort '49152-65535'
        Add-Rule 'AD Web Services from domain members' -Protocol TCP -Port 9389 -Remote $MemberList
    }
    if ($AdminList.Count) { Add-Rule 'RDP from admin IPs' -Protocol TCP -Port 3389 -Remote $AdminList }
    if ($isDhcp) { Add-Rule 'DHCP server' -Protocol UDP -Port 67 }
    if ($BlockSmbEgress) {
        Add-Rule 'Block SMB out to non-internal' -Direction Outbound -Action Block -Protocol TCP -Port 445, 139 -Remote $ExternalList -RuleGroup $EgressGroup
    }
    if ($BlockScriptEgress) {
        foreach ($exe in $EgressPrograms) {
            if (Test-Path $exe) {
                Add-Rule "Block $(Split-Path $exe -Leaf) out to non-internal" -Direction Outbound -Action Block -Program $exe -Remote $ExternalList -RuleGroup $EgressGroup
            }
        }
    }
}

if ($DryRun) {
    Say "`nRules that would be created:" Cyan
    Add-AllRules
    Say "`nDry run finished. Nothing was changed." Green
    return
}

if (-not $Force) {
    $answer = Read-Host "`nApply this? Type YES"
    if ($answer.Trim().ToUpper() -ne 'YES') { Say "Nothing changed."; return }
}

# ------------------------------------------------------------------ apply
$backup = "$Dir\fw_backup_$Stamp.wfw"
& netsh advfirewall export "$backup" | Out-Null
if (-not (Test-Path $backup)) { throw "Firewall backup failed, so nothing was changed." }
if (-not (Test-Path "$Dir\fw_original.wfw")) { Copy-Item $backup "$Dir\fw_original.wfw" }
Say "`nBacked up the current firewall to $backup" Green

Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow `
    -LogBlocked True -LogAllowed False -LogMaxSizeKilobytes 16384 -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
try {
    # Red teams flip this ("block all incoming, ignore allow rules") to take scored services down.
    Set-NetFirewallProfile -Profile Domain, Private, Public -AllowInboundRules True -NotifyOnListen False
} catch { Warn "Couldn't set AllowInboundRules: $($_.Exception.Message)" }

# Clear out a previous run of this script
Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $_.Group -in @($Group, $EgressGroup) } | Remove-NetFirewallRule

# Disable every other inbound allow rule and every block rule (red teams add block rules on DNS or
# on the forwarder's port 9997 to hurt you). Core Networking stays on: it's IPv6 housekeeping and DHCP.
$others = @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object {
    $_.Enabled -eq 'True' -and
    $_.Group -notin @($Group, $EgressGroup) -and
    $_.DisplayGroup -ne 'Core Networking' -and
    (($_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow') -or $_.Action -eq 'Block')
})
$others | Select-Object DisplayName, Direction, Action, DisplayGroup | Format-Table -AutoSize | Out-String -Width 300 |
    Set-Content "$Dir\fw_disabled_$Stamp.txt"
if ($others.Count) { $others | Disable-NetFirewallRule }
Say "Disabled $($others.Count) other rule(s). List: $Dir\fw_disabled_$Stamp.txt" Green

Say "`nCreating rules:" Cyan
Add-AllRules
Say "`nNew rules are live. Test from another box now (list at the bottom of this script)." Green
Say "Undo: .\dc_firewall.ps1 -Undo" Gray

<#
  TEST FROM ANOTHER BOX (Kali, outside the network)
    nslookup <domain> <DC public IP>                         works      (DNS is scored)
    nxc winrm <DC public IP> -u <user> -p '<pass>'           connects   (WinRM is scored)
    nxc smb <DC public IP>                                   times out
    nxc ldap <DC public IP>                                  times out
  FROM THE MSSQL BOX OR THE WORKSTATION
    gpupdate /force                                          succeeds
    nltest /sc_verify:<domain>                               "Success"
  ON THE SCOREBOARD
    DNS and WinRM stay green.
#>
