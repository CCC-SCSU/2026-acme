<#
.SYNOPSIS
    Lists every domain-joined Windows machine.
    
    Per host: name, IP, role, OS, ping, open ports, and (if WinRM or RPC answers) its key services,
    local Administrators, non-default shares, and anything that runs as a domain account
    (services, scheduled tasks, IIS app pools). Those accounts' passwords are saved on that host:
    change them there too, or the service breaks.

.EXAMPLE
    .\inventory-domain.ps1
    .\inventory-domain.ps1 -Name 'SQL*' -NoPortScan
    .\inventory-domain.ps1 -ServiceAccountsFile C:\Backup\service-accounts.txt   # for reset-passwords.ps1 -ExcludeFile
#>
[CmdletBinding()]
param(
    [string]$Name = '*',
    [switch]$IncludeDisabled,
    [switch]$IncludeNonWindows,
    [switch]$NoPortScan,
    [switch]$NoRemote,
    [int[]]$Ports = @(21, 22, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445, 636, 1433, 3268, 3306, 3389, 5432, 5985, 5986, 8080, 8443),
    [ValidateRange(100, 5000)][int]$TimeoutMs = 500,
    [string]$ServiceAccountsFile      # optional: save the domain service account list here
)

$KeyServices   = '(?i)^(W3SVC|FTPSVC|MSFTPSVC|SMTPSVC|MSSQLSERVER|MSSQL\$.*|SQLSERVERAGENT|SQLAgent\$.*|MySQL.*|MariaDB.*|postgresql.*|Apache.*|nginx|Tomcat.*|DNS|NTDS|ADWS|DHCPServer|CertSvc|TermService|WinRM|sshd|Spooler|SNMP|FileZilla.*|hMailServer|RemoteAccess|SplunkForwarder|Sysmon64)$'
$BuiltinNames  = '(?i)^(LocalSystem|NT AUTHORITY\\.*|NT SERVICE\\.*|\.?\\?LocalService|\.?\\?NetworkService|SYSTEM|INTERACTIVE|Users|Administrators)$'

# Start every TCP connect at once, wait once, see which completed
function Test-TcpPorts([string]$Target, [int[]]$PortList, [int]$Timeout) {
    $pending = foreach ($p in $PortList) {
        $c = New-Object Net.Sockets.TcpClient
        try { [pscustomobject]@{ Port = $p; Client = $c; Async = $c.BeginConnect($Target, $p, $null, $null) } } catch { $c.Close() }
    }
    Start-Sleep -Milliseconds $Timeout
    $open = foreach ($x in $pending) {
        try { if ($x.Async.IsCompleted -and $x.Client.Connected) { $x.Port } } catch { }
        try { $x.Client.Close() } catch { }
    }
    @($open | Sort-Object)
}

function Get-Cim($Session, [string]$Class, [string]$Filter, [string]$Namespace = 'root/cimv2') {
    $p = @{ CimSession = $Session; ClassName = $Class; Namespace = $Namespace; ErrorAction = 'Stop'; OperationTimeoutSec = 30 }
    if ($Filter) { $p.Filter = $Filter }
    try { @(Get-CimInstance @p) } catch { @() }
}

# WinRM first, then DCOM (RPC), only on ports that answered
function New-Session([string]$Computer, [bool]$IsLocal, [int[]]$Open, [bool]$Scanned) {
    if ($IsLocal) { try { return @{ S = (New-CimSession -ErrorAction Stop); Via = 'local' } } catch { return $null } }
    foreach ($try in @(@('Wsman', 5985, 'WinRM'), @('Dcom', 135, 'RPC'))) {
        if ($Scanned -and $Open -notcontains $try[1]) { continue }
        try {
            $s = New-CimSession -ComputerName $Computer -SessionOption (New-CimSessionOption -Protocol $try[0]) -OperationTimeoutSec 20 -ErrorAction Stop
            return @{ S = $s; Via = $try[2] }
        } catch { }
    }
    $null
}

# 'CORP\svc_sql' or 'svc_sql@corp.local' -> 'svc_sql' if it's an account in this domain, else ''
function Get-DomainAccount([string]$Raw) {
    $r = "$Raw".Trim()
    if (-not $r -or $r -match $BuiltinNames) { return '' }
    if ($r -match '^([^\\]+)\\(.+)$' -and ($Matches[1] -ieq $netBios -or $Matches[1] -ieq $dnsRoot)) { return $Matches[2] }
    if ($r -match '^([^@]+)@(.+)$' -and $Matches[2] -ieq $dnsRoot) { return $Matches[1] }
    ''
}

try { Import-Module ActiveDirectory -ErrorAction Stop } catch { Write-Host 'ActiveDirectory module missing (run on the DC).' -ForegroundColor Red; exit 1 }
$dom = Get-ADDomain
$netBios = $dom.NetBIOSName
$dnsRoot = $dom.DNSRoot

$all   = @(Get-ADComputer -Filter ("Name -like '{0}'" -f ($Name -replace "'", "''")) -Properties OperatingSystem, IPv4Address, DNSHostName, Enabled, PrimaryGroupID, TrustedForDelegation, LastLogonDate)
$comps = @($all | Where-Object { ($IncludeNonWindows -or "$($_.OperatingSystem)" -like '*Windows*') -and ($IncludeDisabled -or $_.Enabled) } | Sort-Object Name)
$skipped = @($all | Where-Object { $comps -notcontains $_ } | ForEach-Object { $_.Name })
Write-Host "`n=== $dnsRoot : $($comps.Count) computers ===" -ForegroundColor Cyan
if ($skipped.Count) { Write-Host "Skipped (non-Windows, never joined, or disabled): $($skipped -join ', ')" }

$rows = @()
$svcAccounts = @()
foreach ($c in $comps) {
    $target  = if ($c.DNSHostName) { $c.DNSHostName } else { $c.Name }
    $isLocal = ($c.Name -ieq $env:COMPUTERNAME)
    $ip = ''
    try { $ip = @(Resolve-DnsName $target -Type A -ErrorAction Stop | Where-Object { $_.Type -eq 'A' })[0].IPAddress } catch { }
    if (-not $ip) { $ip = "$($c.IPv4Address)" }

    $role = if ($c.PrimaryGroupID -in 516, 521) { 'DC' } elseif ("$($c.OperatingSystem)" -like '*Server*') { 'Server' } else { 'Workstation' }
    $ping = $false
    if ($ip) { $ping = [bool](Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue) }
    $open = @(); $scanned = $false
    if ($ip -and -not $NoPortScan) { $open = @(Test-TcpPorts $ip $Ports $TimeoutMs); $scanned = $true }

    Write-Host ("`n{0}  {1}  {2}  {3}" -f $c.Name, $ip, $role, $c.OperatingSystem) -ForegroundColor White
    Write-Host ("  ping: {0}   open ports: {1}   last logon (AD): {2}" -f $ping, ($open -join ','), $c.LastLogonDate)
    if ($c.TrustedForDelegation -and $role -ne 'DC') { Write-Host '  ! unconstrained delegation on a non-DC' -ForegroundColor Red }

    $via = 'none'
    if (-not $NoRemote -and ($ip -or $isLocal)) {
        $sess = New-Session $target $isLocal $open $scanned
        if ($sess) {
            $via = $sess.Via
            $s = $sess.S
            try {
                $services = Get-Cim $s 'Win32_Service'
                $key = @($services | Where-Object { $_.Name -match $KeyServices } | Sort-Object Name | ForEach-Object { "$($_.Name) ($($_.State))" })
                Write-Host "  key services: $($key -join ', ')"

                if ($role -ne 'DC') {
                    $grp = Get-Cim $s 'Win32_Group' "LocalAccount=TRUE AND SID='S-1-5-32-544'" | Select-Object -First 1
                    if ($grp) {
                        $admins = @(Get-CimAssociatedInstance -CimSession $s -InputObject $grp -Association Win32_GroupUser -ErrorAction SilentlyContinue |
                                    ForEach-Object { "$($_.Domain)\$($_.Name)" })
                        Write-Host "  local admins: $($admins -join ', ')"
                    }
                }

                $shares = @(Get-Cim $s 'Win32_Share' | Where-Object { $_.Name -notmatch '^(ADMIN\$|IPC\$|[A-Z]\$|print\$)$' } | ForEach-Object { "$($_.Name) ($($_.Path))" })
                if ($shares.Count) { Write-Host "  shares: $($shares -join ', ')" }

                # Anything running as a domain account
                $runsAs = @()
                foreach ($x in $services) { $a = Get-DomainAccount $x.StartName; if ($a) { $runsAs += "service $($x.Name) as $a"; $svcAccounts += $a } }
                try {
                    foreach ($t in @(Get-ScheduledTask -CimSession $s -ErrorAction Stop)) {
                        $a = Get-DomainAccount $t.Principal.UserId
                        if ($a) { $runsAs += "task $($t.TaskPath)$($t.TaskName) as $a"; $svcAccounts += $a }
                    }
                } catch { }
                foreach ($p in (Get-Cim $s 'ApplicationPool' '' 'root/WebAdministration')) {
                    $a = Get-DomainAccount $p.ProcessModel.UserName
                    if ($a) { $runsAs += "IIS pool $($p.Name) as $a"; $svcAccounts += $a }
                }
                if ($runsAs.Count) { Write-Host "  runs as domain accounts: $($runsAs -join '; ')" -ForegroundColor Yellow }
            } finally { Remove-CimSession -CimSession $s -ErrorAction SilentlyContinue }
        }
    }
    if ($via -eq 'none' -and -not $NoRemote) { Write-Host '  (no remote details: WinRM/RPC blocked, offline, or no rights)' -ForegroundColor DarkGray }
    $rows += [pscustomobject]@{ Name = $c.Name; IP = $ip; Role = $role; Ping = $ping; Remote = $via; OpenPorts = ($open -join ',') }
}

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
$rows | Format-Table -AutoSize | Out-String -Width 200 | Write-Host

$svcAccounts = @($svcAccounts | Sort-Object -Unique)
Write-Host '=== Domain accounts that run services / tasks / app pools (their password lives on those hosts) ===' -ForegroundColor Cyan
if ($svcAccounts.Count) { $svcAccounts | ForEach-Object { Write-Host "  $_" } } else { Write-Host '  None found on the hosts that answered.' }
if ($ServiceAccountsFile) { $svcAccounts | Set-Content -LiteralPath $ServiceAccountsFile -Encoding ASCII; Write-Host "Saved to $ServiceAccountsFile" }