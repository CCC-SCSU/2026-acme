<#
.SYNOPSIS
    Lists every domain-joined Windows machine with as much detail as it can reach. READ-ONLY: changes nothing.

.DESCRIPTION
    From Active Directory (works even if the host is down):
        name, DNS name, OS + version, IPv4, role (DC / server / workstation), enabled, last logon, created,
        password last set, unconstrained delegation, OU, description
    Live, from this machine:
        DNS resolution, ping, TCP check of common ports (default list below)
    From the host itself, if WinRM (5985) or RPC/DCOM (135) answers - read-only CIM queries:
        OS build, install date, last boot, domain role, make/model, RAM, disks, NICs (IP / MAC / gateway / DNS),
        installed roles, last hotfix, logged-on user, listening TCP/UDP ports with their process,
        non-default shares, local Administrators members, key server services (IIS, SQL, DNS, ...),
        services, scheduled tasks and IIS app pools that run as a user account,
        installed software (only with -Software; slower)
    Output in C:\Backup\reports\inventory-<time>\ :
        summary.csv        one row per host (good for an inventory inject)
        report.html        everything, readable in a browser
        hosts.json         everything, raw
        service-accounts.txt   domain accounts that run services / tasks / app pools anywhere. Pass it to
                               reset-passwords.ps1 -ExcludeFile so you don't break those services.

.EXAMPLE
    .\inventory-domain.ps1
.EXAMPLE
    .\inventory-domain.ps1 -Software                  # include installed programs
.EXAMPLE
    .\inventory-domain.ps1 -Name 'WEB*' -NoPortScan
#>
[CmdletBinding()]
param(
    [string]$Name = '*',
    [switch]$IncludeDisabled,
    [switch]$IncludeNonWindows,
    [switch]$NoPortScan,
    [switch]$NoRemote,
    [switch]$Software,
    [int[]]$Ports = @(21, 22, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445, 636, 1433, 3268, 3306, 3389, 5432, 5985, 5986, 8080, 8443),
    [ValidateRange(100, 5000)][int]$TimeoutMs = 500,
    [string]$OutDir = 'C:\Backup'
)

function Write-Section([string]$Text) { Write-Host ''; Write-Host ('=== {0} ===' -f $Text) -ForegroundColor Cyan }
function Write-Good([string]$Text) { Write-Host ('[+] {0}' -f $Text) -ForegroundColor Green }
function Write-Warn([string]$Text) { Write-Host ('[!] {0}' -f $Text) -ForegroundColor Yellow }
function Write-Bad([string]$Text)  { Write-Host ('[X] {0}' -f $Text) -ForegroundColor Red }
function Write-Info([string]$Text) { Write-Host ('[*] {0}' -f $Text) }

$script:KeyServices = '(?i)^(W3SVC|WAS|IISADMIN|FTPSVC|MSFTPSVC|SMTPSVC|MSSQLSERVER|MSSQL\$.*|SQLSERVERAGENT|SQLAgent\$.*|MySQL.*|MariaDB.*|postgresql.*|Apache.*|nginx|Tomcat.*|DNS|NTDS|Kdc|Netlogon|ADWS|DHCPServer|CertSvc|DFSR|TermService|WinRM|sshd|Docker|MSExchange.*|Spooler|SNMP|vsftpd|FileZilla.*|hMailServer|WDSServer|RemoteAccess)$'
$script:BuiltinStartNames = '(?i)^(LocalSystem|NT AUTHORITY\\.*|NT SERVICE\\.*|\.?\\?LocalService|\.?\\?NetworkService)$'

# ---------------------------------------------------------------- probes
function Test-TcpPorts([string]$Target, [int[]]$PortList, [int]$Timeout) {
    # Starts every connect at once, waits once, then checks which ones completed.
    $pending = @()
    foreach ($p in $PortList) {
        $c = New-Object Net.Sockets.TcpClient
        try { $pending += [pscustomobject]@{ Port = $p; Client = $c; Async = $c.BeginConnect($Target, $p, $null, $null) } }
        catch { $c.Close() }
    }
    Start-Sleep -Milliseconds $Timeout
    $open = @()
    foreach ($x in $pending) {
        try { if ($x.Async.IsCompleted -and $x.Client.Connected) { $open += $x.Port } } catch { }
        try { $x.Client.Close() } catch { }
    }
    @($open | Sort-Object)
}

function Invoke-Cim($Session, [string]$Class, [string]$Filter, [string]$Namespace = 'root/cimv2') {
    try {
        $p = @{ CimSession = $Session; ClassName = $Class; Namespace = $Namespace; ErrorAction = 'Stop'; OperationTimeoutSec = 30 }
        if ($Filter) { $p.Filter = $Filter }
        return @(Get-CimInstance @p)
    } catch { return @() }
}

function New-RemoteSession([string]$Computer, [bool]$IsLocal, [int[]]$OpenPorts, [bool]$Scanned) {
    if ($IsLocal) {
        try { return [pscustomobject]@{ Session = (New-CimSession -ErrorAction Stop); Protocol = 'local' } } catch { return $null }
    }
    $tryWsman = (-not $Scanned) -or ($OpenPorts -contains 5985)
    $tryDcom = (-not $Scanned) -or ($OpenPorts -contains 135)
    if ($tryWsman) {
        try {
            $s = New-CimSession -ComputerName $Computer -SessionOption (New-CimSessionOption -Protocol Wsman) -OperationTimeoutSec 20 -ErrorAction Stop
            return [pscustomobject]@{ Session = $s; Protocol = 'WinRM' }
        } catch { }
    }
    if ($tryDcom) {
        try {
            $s = New-CimSession -ComputerName $Computer -SessionOption (New-CimSessionOption -Protocol Dcom) -OperationTimeoutSec 20 -ErrorAction Stop
            return [pscustomobject]@{ Session = $s; Protocol = 'DCOM' }
        } catch { }
    }
    $null
}

function Get-RemoteSoftware($Session) {
    $hklm = [uint32]2147483650
    $out = @()
    foreach ($root in 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') {
        $keys = @()
        try {
            $r = Invoke-CimMethod -CimSession $Session -Namespace root/default -ClassName StdRegProv -MethodName EnumKey -Arguments @{ hDefKey = $hklm; sSubKeyName = $root } -ErrorAction Stop
            $keys = @($r.sNames)
        } catch { }
        foreach ($k in $keys) {
            if (-not $k) { continue }
            $path = '{0}\{1}' -f $root, $k
            try {
                $n = (Invoke-CimMethod -CimSession $Session -Namespace root/default -ClassName StdRegProv -MethodName GetStringValue -Arguments @{ hDefKey = $hklm; sSubKeyName = $path; sValueName = 'DisplayName' } -ErrorAction Stop).sValue
                if (-not $n) { continue }
                $v = (Invoke-CimMethod -CimSession $Session -Namespace root/default -ClassName StdRegProv -MethodName GetStringValue -Arguments @{ hDefKey = $hklm; sSubKeyName = $path; sValueName = 'DisplayVersion' } -ErrorAction Stop).sValue
                $out += (('{0} {1}' -f $n, $v).Trim())
            } catch { }
        }
    }
    @($out | Sort-Object -Unique)
}

function ConvertTo-AccountName([string]$Raw, [string]$NetBios, [string]$DnsRoot) {
    # Returns the bare sAMAccountName if $Raw is a DOMAIN account (DOMAIN\user or user@domain), else ''.
    $r = ([string]$Raw).Trim()
    if (-not $r -or $r -match $script:BuiltinStartNames) { return '' }
    if ($r -match '^([^\\]+)\\(.+)$') {
        if ($Matches[1] -ieq $NetBios -or $Matches[1] -ieq $DnsRoot) { return $Matches[2] }
        return ''
    }
    if ($r -match '^([^@]+)@(.+)$') {
        if ($Matches[2] -ieq $DnsRoot) { return $Matches[1] }
        return ''
    }
    ''
}

function Get-HostRemoteInfo($Session, [string]$NetBios, [string]$DnsRoot) {
    $info = [ordered]@{}
    $os = Invoke-Cim $Session 'Win32_OperatingSystem' | Select-Object -First 1
    $cs = Invoke-Cim $Session 'Win32_ComputerSystem' | Select-Object -First 1
    if ($os) {
        $info.OSCaption = $os.Caption
        $info.OSBuild = $os.BuildNumber
        $info.Architecture = $os.OSArchitecture
        $info.InstallDate = $os.InstallDate
        $info.LastBoot = $os.LastBootUpTime
    }
    $role = -1
    if ($cs) {
        $role = [int]$cs.DomainRole
        $info.DomainRole = @('Standalone workstation', 'Member workstation', 'Standalone server', 'Member server', 'Backup DC', 'Primary DC')[$role]
        $info.MakeModel = ('{0} {1}' -f $cs.Manufacturer, $cs.Model).Trim()
        $info.MemoryGB = [Math]::Round([double]$cs.TotalPhysicalMemory / 1GB, 1)
        $info.LoggedOnUser = $cs.UserName
    }
    $info.Disks = (@(Invoke-Cim $Session 'Win32_LogicalDisk' 'DriveType=3' | ForEach-Object {
        '{0} {1:N0}/{2:N0} GB free' -f $_.DeviceID, ($_.FreeSpace / 1GB), ($_.Size / 1GB) }) -join '; ')
    $info.NICs = (@(Invoke-Cim $Session 'Win32_NetworkAdapterConfiguration' 'IPEnabled=TRUE' | ForEach-Object {
        '{0} | MAC {1} | GW {2} | DNS {3}' -f ((@($_.IPAddress) | Where-Object { $_ -notmatch ':' }) -join ','), $_.MACAddress,
            (@($_.DefaultIPGateway) -join ','), (@($_.DNSServerSearchOrder) -join ',') }) -join '; ')
    $roles = @(Invoke-Cim $Session 'Win32_ServerFeature' | Where-Object { $_.ParentID -eq 0 } | ForEach-Object { $_.Name })
    $info.Roles = ($roles | Sort-Object) -join '; '

    $hf = @(Invoke-Cim $Session 'Win32_QuickFixEngineering')
    $latest = $null; $latestId = ''
    foreach ($h in $hf) {
        $dt = [datetime]::MinValue
        if ($h.InstalledOn -and [datetime]::TryParse([string]$h.InstalledOn, [ref]$dt) -and $dt -gt $latest) { $latest = $dt; $latestId = $h.HotFixID }
    }
    $info.Hotfixes = $hf.Count
    if ($latest) { $info.LastHotfix = ('{0} ({1:yyyy-MM-dd})' -f $latestId, $latest) } else { $info.LastHotfix = '' }

    # Listening ports with owning process
    $procs = @{}
    foreach ($p in (Invoke-Cim $Session 'Win32_Process')) { $procs[[int]$p.ProcessId] = $p.Name }
    $tcp = @(Invoke-Cim $Session 'MSFT_NetTCPConnection' 'State=2' 'root/StandardCimv2')
    $udp = @(Invoke-Cim $Session 'MSFT_NetUDPEndpoint' '' 'root/StandardCimv2')
    $tcpList = @($tcp | Where-Object { $_.LocalPort -lt 49152 } | ForEach-Object { '{0}/{1}' -f $_.LocalPort, $procs[[int]$_.OwningProcess] } | Sort-Object -Unique)
    $dyn = @($tcp | Where-Object { $_.LocalPort -ge 49152 } | ForEach-Object { $_.LocalPort } | Sort-Object -Unique).Count
    if ($dyn) { $tcpList += ('+{0} dynamic RPC ports' -f $dyn) }
    $info.ListeningTCP = $tcpList -join ', '
    $info.ListeningUDP = (@($udp | Where-Object { $_.LocalPort -lt 49152 } | ForEach-Object { '{0}/{1}' -f $_.LocalPort, $procs[[int]$_.OwningProcess] } | Sort-Object -Unique)) -join ', '

    $info.Shares = (@(Invoke-Cim $Session 'Win32_Share' | Where-Object { $_.Name -notmatch '^(ADMIN\$|IPC\$|[A-Z]\$|print\$)$' } |
        ForEach-Object { '{0} ({1})' -f $_.Name, $_.Path }) -join '; ')

    if ($role -ge 0 -and $role -lt 4) {
        $grp = Invoke-Cim $Session 'Win32_Group' "LocalAccount=TRUE AND SID='S-1-5-32-544'" | Select-Object -First 1
        if ($grp) {
            try {
                $members = @(Get-CimAssociatedInstance -CimSession $Session -InputObject $grp -Association Win32_GroupUser -ErrorAction Stop |
                    ForEach-Object { '{0}\{1}' -f $_.Domain, $_.Name })
                $info.LocalAdmins = $members -join ', '
            } catch { $info.LocalAdmins = '(could not read)' }
        }
    } elseif ($role -ge 4) { $info.LocalAdmins = '(domain controller: see audit-users-groups.ps1)' }

    $svcAccounts = New-Object System.Collections.Generic.List[string]
    $services = @(Invoke-Cim $Session 'Win32_Service')
    $info.KeyServices = (@($services | Where-Object { $_.Name -match $script:KeyServices } | Sort-Object Name |
        ForEach-Object { '{0} ({1})' -f $_.Name, $_.State }) -join ', ')
    $userSvcs = @($services | Where-Object { $_.StartName -and $_.StartName -notmatch $script:BuiltinStartNames })
    $info.ServicesAsUsers = (@($userSvcs | ForEach-Object { '{0} as {1} ({2})' -f $_.Name, $_.StartName, $_.State }) -join '; ')
    foreach ($s in $userSvcs) { $a = ConvertTo-AccountName $s.StartName $NetBios $DnsRoot; if ($a) { $svcAccounts.Add($a) } }

    try {
        $tasks = @(Get-ScheduledTask -CimSession $Session -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })
        $info.CustomTasks = (@($tasks | ForEach-Object {
            $act = (@($_.Actions) | ForEach-Object { ('{0} {1}' -f $_.Execute, $_.Arguments).Trim() }) -join ' & '
            '{0}{1} [{2}] as {3}: {4}' -f $_.TaskPath, $_.TaskName, $_.State, $_.Principal.UserId, $act }) -join '; ')
        foreach ($t in $tasks) { $a = ConvertTo-AccountName $t.Principal.UserId $NetBios $DnsRoot; if ($a) { $svcAccounts.Add($a) } }
    } catch { $info.CustomTasks = '(could not read)' }

    $pools = @(Invoke-Cim $Session 'ApplicationPool' '' 'root/WebAdministration')
    $poolUsers = @($pools | Where-Object { $_.ProcessModel -and $_.ProcessModel.UserName } | ForEach-Object { '{0} as {1}' -f $_.Name, $_.ProcessModel.UserName })
    $info.AppPoolsAsUsers = $poolUsers -join '; '
    foreach ($p in $pools) { if ($p.ProcessModel) { $a = ConvertTo-AccountName $p.ProcessModel.UserName $NetBios $DnsRoot; if ($a) { $svcAccounts.Add($a) } } }

    if ($Software) { $info.Software = (Get-RemoteSoftware $Session) -join '; ' }
    [pscustomobject]@{ Info = $info; ServiceAccounts = @($svcAccounts | Select-Object -Unique) }
}

function ConvertTo-HtmlSafe([string]$Text) { [System.Net.WebUtility]::HtmlEncode($Text) }

# ---------------------------------------------------------------- main
if ($MyInvocation.InvocationName -eq '.') { return }
try { Import-Module ActiveDirectory -ErrorAction Stop } catch { Write-Bad 'ActiveDirectory module missing (run on the DC or install RSAT).'; exit 1 }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportDir = Join-Path $OutDir ('reports\inventory-{0}' -f $stamp)
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null

$domainObj = Get-ADDomain
$netBios = $domainObj.NetBIOSName
$dnsRoot = $domainObj.DNSRoot
Write-Section ('Inventory of {0} (read-only)' -f $dnsRoot)

$props = 'OperatingSystem', 'OperatingSystemVersion', 'IPv4Address', 'DNSHostName', 'LastLogonDate', 'whenCreated', 'Enabled',
         'Description', 'TrustedForDelegation', 'PrimaryGroupID', 'PasswordLastSet', 'CanonicalName'
$all = @(Get-ADComputer -Filter ("Name -like '{0}'" -f ($Name -replace "'", "''")) -Properties $props)
$skippedOs = @($all | Where-Object { [string]$_.OperatingSystem -notlike '*Windows*' })
$comps = @($all | Where-Object { $IncludeNonWindows -or [string]$_.OperatingSystem -like '*Windows*' })
$skippedDisabled = @($comps | Where-Object { -not $_.Enabled })
if (-not $IncludeDisabled) { $comps = @($comps | Where-Object { $_.Enabled }) }
Write-Info ('{0} computer objects in AD; inventorying {1}' -f $all.Count, $comps.Count)
if ($skippedOs.Count -and -not $IncludeNonWindows) { Write-Info ('Skipped non-Windows / never-joined: {0}' -f (($skippedOs | ForEach-Object { $_.Name }) -join ', ')) }
if ($skippedDisabled.Count -and -not $IncludeDisabled) { Write-Info ('Skipped disabled: {0}' -f (($skippedDisabled | ForEach-Object { $_.Name }) -join ', ')) }

$hosts = @()
$allServiceAccounts = New-Object System.Collections.Generic.List[string]
$n = 0
foreach ($c in ($comps | Sort-Object Name)) {
    $n++
    $target = $c.DNSHostName
    if (-not $target) { $target = $c.Name }
    Write-Info ('[{0}/{1}] {2}' -f $n, $comps.Count, $target)
    $isLocal = ($c.Name -ieq $env:COMPUTERNAME)

    $resolved = @()
    try { $resolved = @(Resolve-DnsName -Name $target -Type A -ErrorAction Stop | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress }) } catch { }
    $addr = ''
    if ($resolved.Count) { $addr = $resolved[0] } elseif ($c.IPv4Address) { $addr = [string]$c.IPv4Address }

    $ping = $false
    if ($addr) { try { $ping = [bool](Test-Connection -ComputerName $addr -Count 1 -Quiet -ErrorAction Stop) } catch { } }
    $open = @()
    $scanned = $false
    if ($addr -and -not $NoPortScan) { $open = @(Test-TcpPorts -Target $addr -PortList $Ports -Timeout $TimeoutMs); $scanned = $true }

    $role = 'Workstation'
    if ($c.PrimaryGroupID -in 516, 521) { $role = 'Domain Controller' } elseif ([string]$c.OperatingSystem -like '*Server*') { $role = 'Server' }

    $remote = $null; $remoteVia = 'none'
    if (-not $NoRemote -and ($addr -or $isLocal)) {
        $sess = New-RemoteSession -Computer $target -IsLocal $isLocal -OpenPorts $open -Scanned $scanned
        if ($sess) {
            $remoteVia = $sess.Protocol
            try { $remote = Get-HostRemoteInfo -Session $sess.Session -NetBios $netBios -DnsRoot $dnsRoot }
            finally { Remove-CimSession -CimSession $sess.Session -ErrorAction SilentlyContinue }
        }
    }

    $row = [ordered]@{
        Name = $c.Name; DNSName = $c.DNSHostName; IP = (($resolved + @([string]$c.IPv4Address)) | Where-Object { $_ } | Select-Object -Unique) -join ','
        Role = $role; OS = $c.OperatingSystem; OSVersion = $c.OperatingSystemVersion; Enabled = $c.Enabled
        Ping = $ping; OpenPorts = ($open -join ','); RemoteVia = $remoteVia
        LastLogonAD = $c.LastLogonDate; Created = $c.whenCreated; PwdLastSet = $c.PasswordLastSet
        UnconstrainedDelegation = ($c.TrustedForDelegation -and $role -ne 'Domain Controller')
        OU = ($c.CanonicalName -replace '/[^/]+$', ''); Description = $c.Description
    }
    if ($remote) {
        foreach ($k in $remote.Info.Keys) { $row[$k] = $remote.Info[$k] }
        foreach ($a in $remote.ServiceAccounts) { $allServiceAccounts.Add($a) }
        $row.DomainServiceAccounts = ($remote.ServiceAccounts -join ', ')
    }
    $hosts += [pscustomobject]$row
}

# ---------------------------------------------------------------- output
Write-Section 'Summary'
$hosts | Select-Object Name, IP, Role,
    @{ n = 'OS'; e = { ([string]$_.OS) -replace 'Windows Server', 'Server' -replace ' (Datacenter|Standard|Evaluation|Enterprise|Pro|Education)', '' } },
    Ping, RemoteVia, OpenPorts | Format-Table -AutoSize | Out-String -Width 250 | Write-Host

$noRemote = @($hosts | Where-Object { $_.RemoteVia -eq 'none' })
if ($noRemote.Count) { Write-Warn ('No remote details (WinRM/RPC blocked, offline, or no rights): {0}' -f (($noRemote | ForEach-Object { $_.Name }) -join ', ')) }
$deleg = @($hosts | Where-Object { $_.UnconstrainedDelegation })
if ($deleg.Count) { Write-Bad ('Non-DC hosts with unconstrained delegation: {0}' -f (($deleg | ForEach-Object { $_.Name }) -join ', ')) }

$svcList = @($allServiceAccounts | Sort-Object -Unique)
Write-Section 'Domain accounts that run services / tasks / app pools'
if ($svcList.Count -eq 0) { Write-Good 'None found on the hosts that answered.' }
foreach ($h in $hosts) { if ($h.PSObject.Properties['DomainServiceAccounts'] -and $h.DomainServiceAccounts) { Write-Info ('{0,-16} {1}' -f $h.Name, $h.DomainServiceAccounts) } }

# files: CSV with the commonly asked inventory columns, everything else in JSON/HTML
$csvCols = 'Name', 'DNSName', 'IP', 'Role', 'OS', 'OSVersion', 'OSBuild', 'Enabled', 'Ping', 'OpenPorts', 'RemoteVia', 'LastBoot',
           'LoggedOnUser', 'MakeModel', 'MemoryGB', 'Roles', 'KeyServices', 'ListeningTCP', 'LastHotfix', 'LocalAdmins', 'DomainServiceAccounts', 'OU', 'Description'
$hosts | Select-Object -Property $csvCols | Export-Csv (Join-Path $reportDir 'summary.csv') -NoTypeInformation -Encoding UTF8
$hosts | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $reportDir 'hosts.json') -Encoding UTF8
$svcFile = Join-Path $reportDir 'service-accounts.txt'
$header = @('# Domain accounts that run services, scheduled tasks or IIS app pools (from inventory-domain.ps1, ' + $stamp + ')',
            '# Use with: .\reset-passwords.ps1 -ExcludeFile "' + $svcFile + '"')
($header + $svcList) | Set-Content -LiteralPath $svcFile -Encoding ASCII

$css = 'body{font-family:Segoe UI,Arial,sans-serif;font-size:13px;margin:24px;color:#222}h1{font-size:20px}h2{font-size:16px;margin-top:28px;border-bottom:1px solid #ccc}' +
       'table{border-collapse:collapse;margin:8px 0 16px}td,th{border:1px solid #ccc;padding:3px 8px;text-align:left;vertical-align:top}th{background:#f0f0f0}'
$html = New-Object System.Text.StringBuilder
[void]$html.Append('<!DOCTYPE html><html><head><meta charset="utf-8"><title>Domain inventory</title><style>' + $css + '</style></head><body>')
[void]$html.Append(('<h1>Domain inventory: {0}</h1><p>Generated {1} on {2}. Read-only scan.</p>' -f (ConvertTo-HtmlSafe $dnsRoot), (Get-Date), $env:COMPUTERNAME))
[void]$html.Append((($hosts | Select-Object Name, IP, Role, OS, OSBuild, Ping, OpenPorts, RemoteVia, LastBoot, KeyServices | ConvertTo-Html -Fragment) -join "`n"))
foreach ($h in $hosts) {
    [void]$html.Append(('<h2>{0}</h2>' -f (ConvertTo-HtmlSafe $h.Name)))
    [void]$html.Append((($h | ConvertTo-Html -Fragment -As List) -join "`n"))
}
[void]$html.Append('</body></html>')
$html.ToString() | Set-Content -LiteralPath (Join-Path $reportDir 'report.html') -Encoding UTF8

Write-Section 'Done'
Write-Info ('Reports: {0}' -f $reportDir)
Write-Info ('Service accounts list (for reset-passwords.ps1 -ExcludeFile): {0}' -f $svcFile)
