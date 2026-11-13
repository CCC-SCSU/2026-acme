#Requires -RunAsAdministrator
<#
  bind_check.ps1 - run on the domain controller. Read-only.

  Finds the "bind accounts" other boxes use to log in to LDAP (the mail server's, a website's, SSSD's,
  Splunk's), and checks everything that makes those logins fail or makes them dangerous:
    1. who logs in to LDAP with a password, from which box
    2. each bind account: disabled, locked out, expired, too powerful, lockable by the red team,
       recent failed logins and why, and every IP it logged in from (outside your network = stolen)
    3. LDAP signing / channel binding on this DC (signing blocks plain logins on port 389)
    4. LDAPS (port 636): does this DC have a certificate for it
    5. does this DC's Windows Firewall let each box in on 389 and 636

  powershell -ExecutionPolicy Bypass -File .\bind_check.ps1
  powershell -ExecutionPolicy Bypass -File .\bind_check.ps1 -TestIPs 172.20.242.40 -Accounts svc_mail -InternalNets 172.20.242.0/24
    -TestIPs       boxes to check the firewall for even if they haven't logged in yet (e.g. the mail server)
    -Accounts      bind accounts you already know about (found automatically otherwise)
    -InternalNets  your other internal subnets (this DC's own subnet is included automatically)
#>
[CmdletBinding()]
param(
    [string[]]$Accounts = @(),
    [string[]]$TestIPs = @(),
    [string[]]$InternalNets = @(),
    [int]$MaxEvents = 20000
)
Import-Module ActiveDirectory
$ErrorActionPreference = 'Continue'
$script:problems = 0

function Title($t) { Write-Host "`n== $t ==" -ForegroundColor Cyan }
function Good($t)  { Write-Host "   OK   $t" -ForegroundColor Green }
function Bad($t)   { Write-Host "   BAD  $t" -ForegroundColor Red; $script:problems++ }
function Warn($t)  { Write-Host "   !    $t" -ForegroundColor Yellow }
function Info($t)  { Write-Host "        $t" -ForegroundColor Gray }
function Show($rows) {
    $rows = @($rows)
    if (-not $rows.Count) { Info '(none)'; return }
    $rows | Format-Table -AutoSize -Wrap | Out-String -Width 250 | Write-Host
}

# ------------------------------------------------------------------ IPv4 helpers
function IPNum([string]$ip) {
    $b = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
    return [int64]$b[0] * 16777216 + [int64]$b[1] * 65536 + [int64]$b[2] * 256 + [int64]$b[3]
}
function Test-IPv4([string]$s) { return ($s -match '^\d{1,3}(\.\d{1,3}){3}$') }
# Does $ip fall inside $spec? Handles Any, LocalSubnet, a.b.c.d, a.b.c.d/24, a.b.c.d/255.255.255.0, a-b ranges.
function Test-InSpec([string]$ip, [string]$spec) {
    $spec = "$spec".Trim()
    if ($spec -in @('Any', '*')) { return $true }
    if (-not (Test-IPv4 $ip)) { return $false }
    $n = IPNum $ip
    if ($spec -like 'LocalSubnet*') { return (Test-InAny $ip $script:OwnNets) }
    if ($spec -match '^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$') {
        $lo = $Matches[1]; $hi = $Matches[2]
        return ($n -ge (IPNum $lo) -and $n -le (IPNum $hi))
    }
    if ($spec -match '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,3}(?:\.\d{1,3}){3})$') {
        $base = $Matches[1]; $mask = $Matches[2]
        $size = 4294967296 - (IPNum $mask)
    } elseif ($spec -match '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') {
        $base = $Matches[1]; $size = [int64][math]::Pow(2, 32 - [int]$Matches[2])
    } elseif (Test-IPv4 $spec) {
        return ($n -eq (IPNum $spec))
    } else { return $false }
    $start = [int64]([math]::Floor((IPNum $base) / $size) * $size)
    return ($n -ge $start -and $n -lt $start + $size)
}
function Test-InAny([string]$ip, [string[]]$specs) {
    foreach ($s in $specs) { if (Test-InSpec $ip $s) { return $true } }
    return $false
}

$script:OwnNets = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
                    ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" })
$Internal = @($script:OwnNets) + @($InternalNets)
$domain   = Get-ADDomain

# ------------------------------------------------------------------ event helpers
function Read-Events([int]$id, [string]$extra) {
    $xp = "*[System[EventID=$id]$extra]"
    Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
}
$reasonText = @{ 'C000006A' = 'wrong password'; 'C0000064' = 'no such user'; 'C0000234' = 'account locked out'
                 'C0000072' = 'account disabled'; 'C0000071' = 'password expired'; 'C0000193' = 'account expired'
                 'C0000070' = "not allowed from this computer ('Log On To' list)"; 'C000006F' = 'outside allowed hours'
                 'C0000224' = 'must change password first'; 'C000015B' = 'not granted this kind of logon'; 'C000006D' = 'bad username or password' }
function Get-Reason($status, $sub) {
    try { $code = '{0:X8}' -f [uint32]$sub } catch { $code = '00000000' }
    if ($code -eq '00000000') { try { $code = '{0:X8}' -f [uint32]$status } catch { } }
    if ($reasonText.ContainsKey($code)) { return $reasonText[$code] }
    return "0x$code"
}
# 4624 fields: 5 user, 8 logon type, 18 IP.   4625 fields: 5 user, 7 status, 9 sub-status, 10 logon type, 19 IP
function Convert-4624($e) { [pscustomobject]@{ Account = "$($e.Properties[5].Value)"; Type = [int]$e.Properties[8].Value
                                               IP = "$($e.Properties[18].Value)" -replace '^::ffff:', ''; Time = $e.TimeCreated } }
function Convert-4625($e) { [pscustomobject]@{ Account = "$($e.Properties[5].Value)"; Type = [int]$e.Properties[10].Value
                                               IP = "$($e.Properties[19].Value)" -replace '^::ffff:', ''; Time = $e.TimeCreated
                                               Reason = (Get-Reason $e.Properties[7].Value $e.Properties[9].Value) } }
$typeName = @{ 2 = 'at the keyboard'; 3 = 'network'; 8 = 'LDAP password'; 10 = 'RDP' }

# ================================================================== 1. LDAP password logins
Title '1. Who logs in to LDAP with a password (event 4624 type 8), from which box'
$ldap = @(Read-Events 4624 " and EventData[Data[@Name='LogonType']='8']" | ForEach-Object { Convert-4624 $_ } |
          Where-Object { $_.IP -notin @('-', '', '127.0.0.1', '::1') })
$bindPattern = 'svc|service|bind|ldap|mail|smtp|imap|splunk|sssd|ftp|sql|web'
$ldapSummary = @($ldap | Group-Object Account, IP | ForEach-Object {
    $f = $_.Group[0]
    $guess = 'a person logging in through that box'
    if ($f.Account -match $bindPattern) { $guess = 'BIND / SERVICE ACCOUNT' }
    [pscustomobject]@{ Account = $f.Account; FromIP = $f.IP; Logins = $_.Count; Last = $f.Time; LooksLike = $guess }
} | Sort-Object FromIP, @{ Expression = 'Logins'; Descending = $true })
Show $ldapSummary
Info 'The bind account is usually the one with the most logins from a box. Everyone else from that IP is a person'
Info 'logging in to mail (or the website) through it.'

$failedLdap = @(Read-Events 4625 " and EventData[Data[@Name='LogonType']='8']" | ForEach-Object { Convert-4625 $_ })
if ($failedLdap.Count) {
    Write-Host "`n   Failed LDAP password logins, and why:" -ForegroundColor White
    Show ($failedLdap | Group-Object Account, IP, Reason | ForEach-Object {
        [pscustomobject]@{ Account = $_.Group[0].Account; FromIP = $_.Group[0].IP; Reason = $_.Group[0].Reason; Times = $_.Count; Last = $_.Group[0].Time }
    } | Sort-Object Last -Descending)
}

# ================================================================== 2. each bind account
Title '2. Each bind account'
$candidates  = @($Accounts)
$candidates += @($ldapSummary | Where-Object { $_.LooksLike -like 'BIND*' } | ForEach-Object { $_.Account })
$candidates += @(Get-ADUser -Filter * -Properties Description | Where-Object {
                    $_.SamAccountName -ne 'krbtgt' -and "$($_.SamAccountName) $($_.Description)" -match 'bind|ldap|sssd|mail|splunk' } |
                 ForEach-Object { $_.SamAccountName })
$candidates  = @($candidates | ForEach-Object { ($_ -replace '^.*\\', '') -replace '@.*$', '' } | Where-Object { $_ } | Sort-Object -Unique)
if (-not $candidates.Count) {
    Warn 'No bind accounts found. If you know one, run again with -Accounts <name>.'
}

# Who is in a powerful group (directly or through other groups)
$privGroups = 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Backup Operators',
              'Server Operators', 'Print Operators', 'DnsAdmins', 'Group Policy Creator Owners', 'Remote Management Users', 'Remote Desktop Users'
$privOf = @{}
foreach ($g in $privGroups) {
    foreach ($m in @(Get-ADGroupMember -Identity $g -Recursive -ErrorAction SilentlyContinue)) {
        if (-not $privOf.ContainsKey($m.SamAccountName)) { $privOf[$m.SamAccountName] = @() }
        $privOf[$m.SamAccountName] += $g
    }
}
$defaultPolicy = Get-ADDefaultDomainPasswordPolicy

foreach ($name in $candidates) {
    $u = Get-ADUser -Identity $name -ErrorAction SilentlyContinue -Properties Enabled, LockedOut, AccountExpirationDate, PasswordExpired,
         PasswordLastSet, PasswordNeverExpires, LastBadPasswordAttempt, badPwdCount, Description, LogonWorkstations, ServicePrincipalName
    Write-Host "`n   >> $name" -ForegroundColor White
    if (-not $u) { Bad "No user called '$name' in AD. Anything binding as it fails (deleted, renamed or a typo in the config)."; continue }
    Info $u.DistinguishedName
    if ($u.Description) { Info "Description: $($u.Description)" }

    if ($u.Enabled) { Good 'Enabled' } else { Bad "DISABLED: every login as it fails. Enable-ADAccount $name" }
    if ($u.LockedOut) {
        Bad "LOCKED OUT (last wrong password $($u.LastBadPasswordAttempt)). Unlock-ADAccount $name"
        Info 'If it keeps locking: the box has an old password saved, or the red team is guessing it on purpose.'
    } else { Good 'Not locked out' }
    if ($u.AccountExpirationDate -and $u.AccountExpirationDate -lt (Get-Date)) { Bad "Account EXPIRED on $($u.AccountExpirationDate)" }
    if ($u.PasswordExpired) { Bad 'Password EXPIRED: logins fail until it is changed (in AD and on the box)' }
    Info "Password last changed: $($u.PasswordLastSet)   (if that's newer than the box's config file, the box has the old one)"
    if ($u.PasswordLastSet -gt (Get-Date).AddHours(-24)) { Warn 'Password changed in the last 24 hours. Was the config on the box updated too?' }
    if (-not $u.PasswordNeverExpires -and $defaultPolicy.MaxPasswordAge.TotalDays -gt 0) {
        Warn "Password expires after $([int]$defaultPolicy.MaxPasswordAge.TotalDays) days; the bind breaks then."
    }
    if ($u.badPwdCount -gt 0) { Warn "$($u.badPwdCount) wrong password(s) recently, last at $($u.LastBadPasswordAttempt)" }
    if ($u.LogonWorkstations) { Warn "'Log On To' is limited to: $($u.LogonWorkstations). LDAP logins from Linux send no computer name, so this can block them." }

    if ($privOf.ContainsKey($u.SamAccountName)) {
        Bad "Member of: $(($privOf[$u.SamAccountName] | Sort-Object -Unique) -join ', ')"
        Info 'A bind account only needs to read AD, which any plain user can. Its password sits in a file on another box:'
        Info 'whoever gets that box gets these rights. Make it a plain user (with the box owner, then test a login).'
    } else { Good 'Plain user (not in any admin or remote-access group)' }

    $rp = Get-ADUserResultantPasswordPolicy -Identity $u -ErrorAction SilentlyContinue
    $threshold = $defaultPolicy.LockoutThreshold
    $from = 'Default Domain Policy'
    if ($rp) { $threshold = $rp.LockoutThreshold; $from = "fine-grained policy '$($rp.Name)'" }
    if ($threshold -gt 0) {
        Warn "Locks out after $threshold wrong passwords ($from). The red team can lock it on purpose and take the service down."
    } else { Good "Can't be locked out ($from). Keep its password long and random." }

    # Every login and failure for this account, and where from
    $mine  = @(Read-Events 4624 " and EventData[Data[@Name='TargetUserName']='$($u.SamAccountName)']" | ForEach-Object { Convert-4624 $_ } |
               Where-Object { $_.IP -notin @('-', '', '127.0.0.1', '::1') })
    $fails = @(Read-Events 4625 " and EventData[Data[@Name='TargetUserName']='$($u.SamAccountName)']" | ForEach-Object { Convert-4625 $_ })
    if ($mine.Count) {
        Info 'Logged in from:'
        foreach ($g in ($mine | Group-Object IP, Type)) {
            $f = $g.Group[0]
            $line = '{0,-16} {1,-15} {2,5} times, last {3}' -f $f.IP, $typeName[$f.Type], $g.Count, $f.Time
            if ((Test-IPv4 $f.IP) -and -not (Test-InAny $f.IP $Internal)) { Bad "$line   <- OUTSIDE your networks: someone else has this password" }
            elseif ($f.Type -ne 8) { Warn "$line   <- not an LDAP login. A bind account shouldn't do this." }
            else { Info "   $line" }
        }
    } else { Warn 'No successful logins found in the Security log (not used, broken, or the log has rolled over).' }
    if ($fails.Count) {
        Info 'Failed logins:'
        foreach ($g in ($fails | Group-Object IP, Reason)) {
            $f = $g.Group[0]
            Warn ('{0,-16} {1,-30} {2,5} times, last {3}' -f $f.IP, $f.Reason, $g.Count, $f.Time)
        }
    }
}

# ================================================================== 3. LDAP signing
Title '3. LDAP signing and channel binding on this DC'
$ntds  = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction SilentlyContinue
$integ = $ntds.LDAPServerIntegrity
$cbt   = $ntds.LdapEnforceChannelBinding
if ("$integ" -eq '2') {
    Bad 'LDAP signing is REQUIRED (LDAPServerIntegrity = 2).'
    Info 'Plain password logins on port 389 without TLS are rejected. If the mail server uses ldap:// without TLS, THIS is'
    Info 'why it fails. Either switch the box to ldaps:// (needs section 4 to be OK), or set it back to 1:'
    Info "   Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' LDAPServerIntegrity 1"
    Info "If a GPO sets 'Domain controller: LDAP server signing requirements', change it there or it comes back."
} else {
    $shown = $integ; if ($null -eq $shown) { $shown = 'not set (= 1)' }
    Good "LDAP signing is not required (LDAPServerIntegrity = $shown). Plain password logins on port 389 are allowed."
}
switch ("$cbt") {
    '2'     { Warn 'LDAP channel binding = Always. Older LDAPS clients (some Linux) fail on port 636. Port 389 is not affected.' }
    '1'     { Good 'LDAP channel binding = When supported (clients that support it use it, the rest still work).' }
    default { Good 'LDAP channel binding is not enforced.' }
}
$rejected = Get-WinEvent -FilterHashtable @{ LogName = 'Directory Service'; Id = 2888 } -MaxEvents 1 -ErrorAction SilentlyContinue
if ($rejected) { Bad "Event 2888 at $($rejected.TimeCreated): the DC REJECTED plain LDAP logins because signing is required. Details: Event Viewer > Directory Service." }
$wouldBe = Get-WinEvent -FilterHashtable @{ LogName = 'Directory Service'; Id = 2887 } -MaxEvents 1 -ErrorAction SilentlyContinue
if ($wouldBe) { Info "Event 2887 at $($wouldBe.TimeCreated): plain LDAP logins are happening. They'd break if you required signing." }

# ================================================================== 4. LDAPS
Title '4. LDAPS (port 636): does this DC have a certificate for it?'
$fqdn  = "$env:COMPUTERNAME.$($domain.DNSRoot)"
$certs = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) -and ($_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.1') })
$match = @($certs | Where-Object { @($_.DnsNameList.Unicode) -contains $fqdn -or $_.Subject -match [regex]::Escape($fqdn) })
if ($match.Count) {
    Good "Certificate for $fqdn found (expires $($match[0].NotAfter), issued by $($match[0].Issuer)). ldaps:// works."
    Info 'Linux boxes must trust the issuer, or use TLS_REQCERT allow in their LDAP settings, or LDAPS fails on their side.'
} elseif ($certs.Count) {
    Warn "Server certificates exist, but none names $fqdn. Clients connecting by that name will reject LDAPS."
} else {
    Warn 'No certificate: ldaps:// to this DC fails. Plain ldap:// on 389 still works unless signing is required (section 3).'
}

# ================================================================== 5. firewall
Title "5. Does this DC's Windows Firewall let each box in on LDAP (389) and LDAPS (636)?"
$sources = @(@($ldap | ForEach-Object { $_.IP }) + @($TestIPs) | Where-Object { Test-IPv4 $_ } | Sort-Object -Unique)
if (-not $sources.Count) { Warn 'No boxes to check. Run again with -TestIPs <mail server IP>.' }

$active = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {
    switch ("$($_.NetworkCategory)") { 'DomainAuthenticated' { 'Domain' } 'Private' { 'Private' } default { 'Public' } } } | Sort-Object -Unique)
$fwOn = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object { $_.Name -in $active -and "$($_.Enabled)" -eq 'True' })
$rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound | Where-Object { "$($_.Enabled)" -eq 'True' })
$pf = @{}; foreach ($f in @(Get-NetFirewallPortFilter -PolicyStore ActiveStore)) { $pf[$f.InstanceID] = $f }
$af = @{}; foreach ($f in @(Get-NetFirewallAddressFilter -PolicyStore ActiveStore)) { $af[$f.InstanceID] = $f }
$joined = @($rules | Where-Object { $pf.ContainsKey($_.InstanceID) }).Count -gt 0

function Get-PortFilter($r)    { if ($joined) { return $pf[$r.InstanceID] } else { return ($r | Get-NetFirewallPortFilter) } }
function Get-AddressFilter($r) { if ($joined) { return $af[$r.InstanceID] } else { return ($r | Get-NetFirewallAddressFilter) } }
function Test-Port($filter, [int]$port) {
    if (-not $filter) { return $false }
    if ("$($filter.Protocol)" -notin @('TCP', 'Any', '6')) { return $false }
    foreach ($lp in @($filter.LocalPort)) {
        if ("$lp" -eq 'Any') { return $true }
        if ("$lp" -match '^(\d+)-(\d+)$') { if ($port -ge [int]$Matches[1] -and $port -le [int]$Matches[2]) { return $true } }
        elseif ("$lp" -match '^\d+$' -and [int]"$lp" -eq $port) { return $true }
    }
    return $false
}
function Test-Profile($r) {
    $p = "$($r.Profile)"
    if ($p -eq 'Any') { return $true }
    foreach ($x in $active) { if ($p -match $x) { return $true } }
    return $false
}
function Get-Verdict([string]$ip, [int]$port) {
    if (-not $fwOn.Count) { return 'allowed (firewall is off)' }
    $allow = $null; $block = $null
    foreach ($r in $rules) {
        if (-not (Test-Profile $r)) { continue }
        if (-not (Test-Port (Get-PortFilter $r) $port)) { continue }
        $a = Get-AddressFilter $r
        if ($a -and -not (Test-InAny $ip @($a.RemoteAddress))) { continue }
        if ("$($r.Action)" -eq 'Block') { $block = $r.DisplayName } elseif (-not $allow) { $allow = $r.DisplayName }
    }
    if ($block) { return "BLOCKED by rule '$block'" }
    if ($allow) { return "allowed by rule '$allow'" }
    return 'BLOCKED (no rule allows it)'
}
$liveIPs = @(Get-NetTCPConnection -State Established -LocalPort 389, 636 -ErrorAction SilentlyContinue |
             ForEach-Object { $_.RemoteAddress -replace '^::ffff:', '' } | Sort-Object -Unique)
foreach ($ip in $sources) {
    $v389 = Get-Verdict $ip 389
    $v636 = Get-Verdict $ip 636
    $now  = if ($liveIPs -contains $ip) { 'yes' } else { 'no' }
    $line = '{0,-16} 389: {1}   |   636: {2}   |   connected now: {3}' -f $ip, $v389, $v636, $now
    if ($v389 -like 'BLOCKED*') { Bad $line } else { Good $line }
}
Info 'This only covers the DC itself. The Palo Alto or VyOS between the boxes can also block LDAP. Test from the mail box:'
Info "   nc -zv <DC IP> 389      then:  ldapsearch -x -H ldap://<DC IP> -D 'svc_mail@$($domain.DNSRoot)' -W -b '$($domain.DistinguishedName)' '(sAMAccountName=<a user>)' dn"

Title 'Summary'
if ($script:problems) { Write-Host "   $($script:problems) problem(s) marked BAD above." -ForegroundColor Red }
else { Write-Host '   No problems found on the DC side. If binds still fail, check the config on the box and the network firewall.' -ForegroundColor Green }