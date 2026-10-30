<#
.SYNOPSIS
    Backs up DNS, Active Directory, IIS/web content and databases into one locked, hash-manifested folder.

.DESCRIPTION
    Detects what the box runs and backs up only that:
      DNS        every zone exported to a zone file + records as CSV/XML, server config, DNS registry key
      AD (DC)    users/groups/computers/OUs (XML + CSV), group membership, GPOs (Backup-GPO + HTML report),
                 gPLinks, ACL SDDL of the domain root/AdminSDHolder/privileged groups, SYSVOL copy,
                 optional system state (-SystemState) and optional IFM copy of ntds.dit (-IncludeNtdsIfm)
      Web        IIS config (appcmd backup), every site's physical path, XAMPP/WAMP/Apache/nginx roots,
                 optional export of HTTPS certificates (-ExportIisCerts)
      Databases  SQL Server (COPY_ONLY .bak of every database), MySQL/MariaDB (mysqldump),
                 PostgreSQL (pg_dumpall)
      Firewall   netsh advfirewall export
    Writes manifest.csv (SHA256 of every file) and RESTORE.txt. -Verify <folder> re-checks a backup
    against its manifest so you can tell if red team touched it.

.EXAMPLE
    .\backup-all.ps1
.EXAMPLE
    .\backup-all.ps1 -Zip -CopyTo E:\
.EXAMPLE
    .\backup-all.ps1 -Verify C:\Backup\backup-DC01-20261031-091500
#>
[CmdletBinding()]
param(
    [string]$Destination = 'C:\Backup',
    [string]$CopyTo,
    [switch]$Zip,
    [switch]$SkipDns,
    [switch]$SkipAD,
    [switch]$SkipWeb,
    [switch]$SkipDatabases,
    [switch]$SystemState,
    [string]$SystemStateTarget,
    [switch]$IncludeNtdsIfm,
    [switch]$ExportIisCerts,
    [string[]]$ExtraPaths,
    [string]$SqlUser,
    [string]$MySqlUser = 'root',
    [string]$PostgresUser = 'postgres',
    [switch]$NoDatabasePrompt,
    [string]$Verify
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

$script:Results = New-Object System.Collections.Generic.List[object]
function Add-Result([string]$Component, [string]$Status, [string]$Detail) {
    $script:Results.Add([pscustomobject]@{ Component = $Component; Status = $Status; Detail = $Detail })
    switch ($Status) {
        'OK'      { Write-Good ('{0}: {1}' -f $Component, $Detail) }
        'Skipped' { Write-Info ('{0}: skipped ({1})' -f $Component, $Detail) }
        'Partial' { Write-Warn ('{0}: partial - {1}' -f $Component, $Detail) }
        default   { Write-Bad ('{0}: {1} - {2}' -f $Component, $Status, $Detail) }
    }
}

function ConvertFrom-SecureStringPlain([Security.SecureString]$Secure) {
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}

function Invoke-Robocopy([string]$Source, [string]$Dest) {
    New-Item -ItemType Directory -Path $Dest -Force | Out-Null
    & robocopy.exe $Source $Dest /E /XJ /B /COPY:DAT /R:1 /W:1 /NFL /NDL /NP /NJH /NJS | Out-Null
    return ($LASTEXITCODE -lt 8)
}

function Protect-Folder([string]$Path) {
    & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
}

function Get-SafeName([string]$Text) {
    if ($Text -eq '.') { return 'root' }
    (($Text -replace '[^A-Za-z0-9\.\-_]+', '_').Trim('_'))
}

function Get-RecordDataText($Record) {
    try {
        $parts = @()
        foreach ($p in $Record.RecordData.CimInstanceProperties) {
            if ($null -ne $p.Value -and ('{0}' -f $p.Value) -ne '') { $parts += ('{0}={1}' -f $p.Name, $p.Value) }
        }
        return ($parts -join '; ')
    } catch { return '' }
}

# ---------------------------------------------------------------- DNS
function Backup-Dns([string]$Root) {
    if (-not (Get-Service -Name DNS -ErrorAction SilentlyContinue)) { Add-Result 'DNS' 'Skipped' 'DNS Server role not installed'; return }
    if (-not (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue)) { Add-Result 'DNS' 'FAILED' 'DnsServer PowerShell module missing'; return }
    $dir = Join-Path $Root 'dns'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $stamp = Get-Date -Format 'yyyyMMddHHmmss'
    $ok = 0; $fail = @()
    $zones = @(Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -ne 'Forwarder' })
    foreach ($z in $zones) {
        $safe = Get-SafeName $z.ZoneName
        try {
            $file = 'ccdc-{0}-{1}.dns' -f $safe, $stamp
            Export-DnsServerZone -Name $z.ZoneName -FileName $file -ErrorAction Stop
            Move-Item -LiteralPath (Join-Path $env:windir ('System32\dns\{0}' -f $file)) -Destination (Join-Path $dir ('{0}.dns' -f $safe)) -Force
            $recs = @(Get-DnsServerResourceRecord -ZoneName $z.ZoneName -ErrorAction Stop)
            $recs | Export-Clixml -Path (Join-Path $dir ('{0}.records.xml' -f $safe))
            $recs | Select-Object HostName, RecordType, @{ n = 'TTL'; e = { $_.TimeToLive } }, @{ n = 'Data'; e = { Get-RecordDataText $_ } } |
                Export-Csv -Path (Join-Path $dir ('{0}.records.csv' -f $safe)) -NoTypeInformation -Encoding UTF8
            $ok++
        } catch { $fail += ('{0}: {1}' -f $z.ZoneName, $_.Exception.Message) }
    }
    Get-DnsServerZone | Select-Object ZoneName, ZoneType, IsDsIntegrated, ReplicationScope, DynamicUpdate, IsReverseLookupZone, SecureSecondaries |
        Export-Csv (Join-Path $dir 'zones.csv') -NoTypeInformation -Encoding UTF8
    try { Get-DnsServer -WarningAction SilentlyContinue -ErrorAction Stop | Export-Clixml (Join-Path $dir 'dns-server-config.xml') } catch { }
    try { Get-DnsServerForwarder | Export-Clixml (Join-Path $dir 'forwarders.xml') } catch { }
    & reg.exe export 'HKLM\SYSTEM\CurrentControlSet\Services\DNS' (Join-Path $dir 'dns-service.reg') /y | Out-Null
    if ($fail.Count) { Add-Result 'DNS' 'Partial' ('{0} zones exported; failed: {1}' -f $ok, ($fail -join ' | ')) }
    else { Add-Result 'DNS' 'OK' ('{0} zones -> {1}' -f $ok, $dir) }
}

# ---------------------------------------------------------------- Active Directory
function Backup-AD([string]$Root) {
    if ((Get-CimInstance Win32_ComputerSystem).DomainRole -lt 4) { Add-Result 'Active Directory' 'Skipped' 'not a domain controller'; return }
    try { Import-Module ActiveDirectory -ErrorAction Stop } catch { Add-Result 'Active Directory' 'FAILED' 'ActiveDirectory module missing'; return }
    $dir = Join-Path $Root 'ad'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $domainObj = Get-ADDomain
    $dn = $domainObj.DistinguishedName
    $dsid = $domainObj.DomainSID.Value
    $notes = @(); $problems = @()

    try {
        Get-ADUser -Filter * -Properties * | Export-Clixml (Join-Path $dir 'users.xml')
        Get-ADGroup -Filter * -Properties * | Export-Clixml (Join-Path $dir 'groups.xml')
        Get-ADComputer -Filter * -Properties * | Export-Clixml (Join-Path $dir 'computers.xml')
        Get-ADOrganizationalUnit -Filter * -Properties * | Export-Clixml (Join-Path $dir 'ous.xml')
        Get-ADUser -Filter * -Properties Enabled, memberOf, whenCreated, whenChanged, description |
            Select-Object SamAccountName, Enabled, whenCreated, whenChanged, Description,
                @{ n = 'MemberOf'; e = { (@($_.memberOf) | ForEach-Object { (($_ -split ',')[0] -replace '^CN=', '') }) -join '; ' } } |
            Export-Csv (Join-Path $dir 'users.csv') -NoTypeInformation -Encoding UTF8
        $rows = foreach ($g in @(Get-ADGroup -Filter * -Properties member)) {
            foreach ($m in @($g.member)) { if ($m) { [pscustomobject]@{ Group = $g.Name; MemberDN = $m } } }
        }
        $rows | Export-Csv (Join-Path $dir 'group-membership.csv') -NoTypeInformation -Encoding UTF8
        $domainObj | Export-Clixml (Join-Path $dir 'domain.xml')
        Get-ADForest | Export-Clixml (Join-Path $dir 'forest.xml')
        Get-ADDefaultDomainPasswordPolicy | Export-Clixml (Join-Path $dir 'password-policy.xml')
        $notes += 'objects'
    } catch { $problems += ('objects: {0}' -f $_.Exception.Message) }

    try {
        $targets = @($dn, "CN=AdminSDHolder,CN=System,$dn", $domainObj.DomainControllersContainer)
        foreach ($s in @("$dsid-512", "$dsid-519", "$dsid-518", 'S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-551')) {
            try { $targets += (Get-ADGroup -Identity $s -ErrorAction Stop).DistinguishedName } catch { }
        }
        $acl = foreach ($t in $targets) { [pscustomobject]@{ Object = $t; Sddl = (Get-Acl -Path ('AD:{0}' -f $t)).Sddl } }
        $acl | Export-Csv (Join-Path $dir 'acl-sddl.csv') -NoTypeInformation -Encoding UTF8
        $links = @([pscustomobject]@{ Target = $dn; gPLink = (Get-ADObject -Identity $dn -Properties gPLink).gPLink })
        $links += @(Get-ADOrganizationalUnit -Filter * -Properties gPLink | Select-Object @{ n = 'Target'; e = { $_.DistinguishedName } }, gPLink)
        $links | Export-Csv (Join-Path $dir 'gplinks.csv') -NoTypeInformation -Encoding UTF8
        $notes += 'ACLs + GPO links'
    } catch { $problems += ('ACLs: {0}' -f $_.Exception.Message) }

    try {
        Import-Module GroupPolicy -ErrorAction Stop
        $gpoDir = Join-Path $dir 'GPO'
        New-Item -ItemType Directory -Path $gpoDir -Force | Out-Null
        Backup-GPO -All -Path $gpoDir -ErrorAction Stop | Select-Object DisplayName, GpoId, Id |
            Export-Csv (Join-Path $dir 'gpo-backups.csv') -NoTypeInformation -Encoding UTF8
        Get-GPOReport -All -ReportType Html -Path (Join-Path $dir 'gpo-report.html')
        $notes += 'GPOs'
    } catch { $problems += ('GPOs: {0}' -f $_.Exception.Message) }

    try {
        # Netlogon's SysVol value is ...\SYSVOL\sysvol, and its <domain> entry is a junction to ...\SYSVOL\domain.
        # Copy the real folder, because robocopy /XJ skips junctions.
        $sysvolRoot = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters').SysVol
        $src = Join-Path (Split-Path -Parent $sysvolRoot) 'domain'
        if (-not (Test-Path -LiteralPath $src)) { $src = Join-Path $sysvolRoot $domainObj.DNSRoot }
        if (Invoke-Robocopy $src (Join-Path $dir 'SYSVOL')) { $notes += 'SYSVOL' } else { $problems += 'SYSVOL copy had errors' }
    } catch { $problems += ('SYSVOL: {0}' -f $_.Exception.Message) }

    try {
        $rb = Get-ADOptionalFeature -Filter "Name -like 'Recycle Bin Feature'"
        if ($rb -and @($rb.EnabledScopes).Count -eq 0) {
            Write-Warn 'AD Recycle Bin is OFF: deleted users/OUs cannot be restored with Restore-ADObject. Enabling it (Enable-ADOptionalFeature) is permanent - team decision.'
            $notes += 'Recycle Bin OFF'
        } elseif ($rb) { $notes += 'Recycle Bin on' }
    } catch { }

    if ($SystemState) {
        if (-not $SystemStateTarget) { $problems += 'system state needs -SystemStateTarget (a volume other than C:, e.g. E:)' }
        else {
            try {
                if (-not (Get-WindowsFeature -Name Windows-Server-Backup).Installed) {
                    Write-Info 'Installing Windows Server Backup feature...'
                    Install-WindowsFeature -Name Windows-Server-Backup | Out-Null
                }
                Write-Info 'Running system state backup (often 20+ minutes)...'
                & wbadmin.exe start systemstatebackup ('-backupTarget:{0}' -f $SystemStateTarget) -quiet
                if ($LASTEXITCODE -eq 0) { $notes += ('system state -> {0}' -f $SystemStateTarget) } else { $problems += ('wbadmin exit {0}' -f $LASTEXITCODE) }
            } catch { $problems += ('system state: {0}' -f $_.Exception.Message) }
        }
    }

    if ($IncludeNtdsIfm) {
        $ifm = Join-Path $dir 'IFM'
        Write-Warn 'IFM copies ntds.dit + SYSTEM hive = every password hash in the domain. Move it off this box.'
        if ($ifm -match '\s') { $problems += 'IFM path contains spaces; use a -Destination without spaces' }
        else {
            & ntdsutil.exe 'activate instance ntds' 'ifm' ('create full {0}' -f $ifm) 'quit' 'quit' | Out-Null
            if (Test-Path -LiteralPath (Join-Path $ifm 'Active Directory\ntds.dit')) { $notes += 'IFM (ntds.dit)' } else { $problems += 'IFM failed' }
        }
    }

    if ($problems.Count) { Add-Result 'Active Directory' 'Partial' (($notes -join ', ') + ' | problems: ' + ($problems -join ' | ')) }
    else { Add-Result 'Active Directory' 'OK' (($notes -join ', ') + ' -> ' + $dir) }
}

# ---------------------------------------------------------------- Web
function Export-IisCertificates([string]$Dir) {
    $out = @()
    $hashes = @(& netsh.exe http show sslcert | Select-String -Pattern 'Certificate Hash\s*:\s*([0-9a-fA-F]+)' |
        ForEach-Object { $_.Matches[0].Groups[1].Value.ToUpperInvariant() } | Select-Object -Unique)
    if ($hashes.Count -eq 0) { return @('no HTTPS bindings found') }
    $pw = Read-Host -AsSecureString 'Password to protect exported PFX files'
    New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    foreach ($h in $hashes) {
        $cert = $null
        foreach ($store in 'My', 'WebHosting') {
            $p = 'Cert:\LocalMachine\{0}\{1}' -f $store, $h
            if (Test-Path -LiteralPath $p) { $cert = Get-Item -LiteralPath $p; break }
        }
        if (-not $cert) { $out += ('cert {0} not found' -f $h); continue }
        try {
            Export-PfxCertificate -Cert $cert -FilePath (Join-Path $Dir ('{0}.pfx' -f $h)) -Password $pw -ErrorAction Stop | Out-Null
            $out += ('exported {0}' -f $cert.Subject)
        } catch {
            Export-Certificate -Cert $cert -FilePath (Join-Path $Dir ('{0}.cer' -f $h)) | Out-Null
            $out += ('{0}: private key not exportable, public cert only' -f $cert.Subject)
        }
    }
    $out
}

function Backup-Web([string]$Root) {
    $dir = Join-Path $Root 'web'
    $notes = @(); $any = $false
    $inetsrv = Join-Path $env:windir 'System32\inetsrv'
    $appcmd = Join-Path $inetsrv 'appcmd.exe'
    if (Test-Path -LiteralPath $appcmd) {
        $any = $true
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $name = 'ccdc-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
        & $appcmd add backup $name | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Invoke-Robocopy (Join-Path $inetsrv ('backup\{0}' -f $name)) (Join-Path $dir ('iis-config\{0}' -f $name)) | Out-Null
            $notes += ('IIS config backup {0}' -f $name)
        } else { $notes += 'appcmd add backup FAILED' }
        Invoke-Robocopy (Join-Path $inetsrv 'config') (Join-Path $dir 'iis-config\config-folder') | Out-Null
        (& $appcmd list site) | Set-Content -LiteralPath (Join-Path $dir 'iis-sites.txt') -Encoding UTF8
        (& $appcmd list apppool) | Set-Content -LiteralPath (Join-Path $dir 'iis-apppools.txt') -Encoding UTF8
        $paths = @(& $appcmd list vdir /text:physicalPath) | Where-Object { $_ } |
            ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim()) } | Select-Object -Unique
        foreach ($p in $paths) {
            if (Test-Path -LiteralPath $p -PathType Container) {
                if (Invoke-Robocopy $p (Join-Path $dir ('content\{0}' -f (Get-SafeName $p)))) { $notes += ('site content {0}' -f $p) }
                else { $notes += ('content copy errors {0}' -f $p) }
            }
        }
        if ($ExportIisCerts) { $notes += @(Export-IisCertificates (Join-Path $dir 'certs')) }
    }
    $candidates = @('C:\xampp\htdocs', 'C:\xampp\apache\conf', 'C:\xampp\php\php.ini', 'C:\wamp64\www', 'C:\wamp\www',
                    'C:\Apache24\htdocs', 'C:\Apache24\conf', 'C:\nginx\html', 'C:\nginx\conf', 'C:\php\php.ini') + @($ExtraPaths)
    foreach ($p in $candidates) {
        if (-not $p -or -not (Test-Path -LiteralPath $p)) { continue }
        $any = $true
        $dest = Join-Path $dir ('other\{0}' -f (Get-SafeName $p))
        if (Test-Path -LiteralPath $p -PathType Container) {
            if (Invoke-Robocopy $p $dest) { $notes += $p } else { $notes += ('copy errors {0}' -f $p) }
        } else {
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            Copy-Item -LiteralPath $p -Destination $dest -Force
            $notes += $p
        }
    }
    if (-not $any) { Add-Result 'Web' 'Skipped' 'no IIS or common web roots found'; return }
    Add-Result 'Web' 'OK' ($notes -join '; ')
}

# ---------------------------------------------------------------- Databases
function Find-SqlCmd {
    $c = Get-Command sqlcmd.exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    foreach ($g in @('C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\*\Tools\Binn\SQLCMD.EXE',
                     'C:\Program Files\Microsoft SQL Server\*\Tools\Binn\SQLCMD.EXE',
                     'C:\Program Files (x86)\Microsoft SQL Server\*\Tools\Binn\SQLCMD.EXE')) {
        $f = Get-ChildItem -Path $g -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($f) { return $f.FullName }
    }
    $null
}

function Backup-SqlServer([string]$Root) {
    $instKey = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
    if (-not (Test-Path -LiteralPath $instKey)) { return }
    $sqlcmd = Find-SqlCmd
    if (-not $sqlcmd) { Add-Result 'SQL Server' 'FAILED' 'SQL Server is installed but sqlcmd.exe was not found'; return }
    $dir = Join-Path $Root 'databases\sqlserver'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $auth = @('-E')
    if ($SqlUser) {
        $env:SQLCMDPASSWORD = ConvertFrom-SecureStringPlain (Read-Host -AsSecureString ('SQL password for {0}' -f $SqlUser))
        $auth = @('-U', $SqlUser)
    }
    try {
        $inst = Get-ItemProperty -LiteralPath $instKey
        foreach ($p in $inst.PSObject.Properties) {
            if ($p.Name -in 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider') { continue }
            $instName = $p.Name; $instId = [string]$p.Value
            $server = 'localhost'
            if ($instName -ne 'MSSQLSERVER') { $server = 'localhost\{0}' -f $instName }
            $bkDir = (Get-ItemProperty -LiteralPath ('HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\{0}\MSSQLServer' -f $instId) -ErrorAction SilentlyContinue).BackupDirectory
            if (-not $bkDir) { Add-Result ('SQL {0}' -f $instName) 'FAILED' 'no BackupDirectory in registry'; continue }
            $dbs = @(& $sqlcmd -S $server @auth -b -h -1 -W -Q "SET NOCOUNT ON; SELECT name FROM sys.databases WHERE name <> 'tempdb' AND state_desc = 'ONLINE'" 2>&1)
            if ($LASTEXITCODE -ne 0) {
                Add-Result ('SQL {0}' -f $instName) 'FAILED' ('cannot list databases (not sysadmin? try -SqlUser sa): {0}' -f (($dbs | Out-String).Trim()))
                continue
            }
            $done = @(); $failed = @()
            foreach ($db in $dbs) {
                $db = ([string]$db).Trim()
                if (-not $db) { continue }
                $bak = Join-Path $bkDir ('ccdc_{0}_{1}.bak' -f (Get-SafeName $db), $stamp)
                $q = "BACKUP DATABASE [{0}] TO DISK = N'{1}' WITH COPY_ONLY, INIT, CHECKSUM" -f ($db -replace '\]', ']]'), ($bak -replace "'", "''")
                $null = & $sqlcmd -S $server @auth -b -Q $q 2>&1
                if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $bak)) { Copy-Item -LiteralPath $bak -Destination $dir -Force; $done += $db }
                else { $failed += $db }
            }
            $status = 'OK'
            if ($failed.Count) { $status = 'Partial' }
            Add-Result ('SQL {0}' -f $instName) $status (('backed up: {0}' -f ($done -join ', ')) + $(if ($failed.Count) { '; failed: ' + ($failed -join ', ') } else { '' }))
        }
    } finally { Remove-Item Env:\SQLCMDPASSWORD -ErrorAction SilentlyContinue }
}

function Find-MySqlDump {
    $found = @()
    $svc = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -match 'mysqld|mariadbd' })
    foreach ($s in $svc) {
        if ($s.PathName -match '^\s*"?([^"]+?\.exe)') {
            $bin = Split-Path -Parent $Matches[1]
            foreach ($n in 'mysqldump.exe', 'mariadb-dump.exe') {
                $p = Join-Path $bin $n
                if (Test-Path -LiteralPath $p) { $found += $p }
            }
        }
    }
    foreach ($g in @('C:\xampp\mysql\bin\mysqldump.exe', 'C:\Program Files\MySQL\*\bin\mysqldump.exe', 'C:\Program Files\MariaDB*\bin\mysqldump.exe',
                     'C:\wamp64\bin\mysql\*\bin\mysqldump.exe', 'C:\wamp\bin\mysql\*\bin\mysqldump.exe')) {
        $found += @(Get-ChildItem -Path $g -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    }
    [pscustomobject]@{ Dump = ($found | Select-Object -First 1); HasServer = ($svc.Count -gt 0 -or (Test-Path 'C:\xampp\mysql\data')) }
}

function Backup-MySql([string]$Root) {
    $f = Find-MySqlDump
    if (-not $f.HasServer) { return }
    if (-not $f.Dump) { Add-Result 'MySQL/MariaDB' 'FAILED' 'server found but mysqldump.exe not found'; return }
    $pwPlain = ''
    if (-not $NoDatabasePrompt) { $pwPlain = ConvertFrom-SecureStringPlain (Read-Host -AsSecureString ("MySQL password for '{0}' (Enter if blank)" -f $MySqlUser)) }
    $dir = Join-Path $Root 'databases\mysql'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $cnf = Join-Path $env:TEMP ('ccdc-{0}.cnf' -f [guid]::NewGuid())
    try {
        $esc = ($pwPlain -replace '\\', '\\') -replace '"', '\"'
        Set-Content -LiteralPath $cnf -Value @('[client]', ('user={0}' -f $MySqlUser), ('password="{0}"' -f $esc)) -Encoding Ascii
        & icacls.exe $cnf /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F' | Out-Null
        $out = Join-Path $dir ('all-databases-{0}.sql' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        $err = & $f.Dump ('--defaults-extra-file={0}' -f $cnf) '--all-databases' '--single-transaction' '--routines' '--events' '--triggers' ('--result-file={0}' -f $out) 2>&1
        if ($LASTEXITCODE -eq 0) { Add-Result 'MySQL/MariaDB' 'OK' $out } else { Add-Result 'MySQL/MariaDB' 'FAILED' (($err | Out-String).Trim()) }
    } finally { Remove-Item -LiteralPath $cnf -Force -ErrorAction SilentlyContinue }
}

function Backup-Postgres([string]$Root) {
    $svc = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -match 'pg_ctl|postgres' })
    if ($svc.Count -eq 0) { return }
    $dump = Get-ChildItem -Path 'C:\Program Files\PostgreSQL\*\bin\pg_dumpall.exe' -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $dump) { Add-Result 'PostgreSQL' 'FAILED' 'service found but pg_dumpall.exe not found'; return }
    $dir = Join-Path $Root 'databases\postgres'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $out = Join-Path $dir ('pg_dumpall-{0}.sql' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    if (-not $NoDatabasePrompt) { $env:PGPASSWORD = ConvertFrom-SecureStringPlain (Read-Host -AsSecureString ("PostgreSQL password for '{0}'" -f $PostgresUser)) }
    try {
        $err = & $dump.FullName -U $PostgresUser -h localhost -f $out 2>&1
        if ($LASTEXITCODE -eq 0) { Add-Result 'PostgreSQL' 'OK' $out } else { Add-Result 'PostgreSQL' 'FAILED' (($err | Out-String).Trim()) }
    } finally { Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue }
}

# ---------------------------------------------------------------- manifest / restore notes
function Write-Manifest([string]$Root) {
    $rows = Get-ChildItem -LiteralPath $Root -Recurse -File -Force | Where-Object { $_.Name -ne 'manifest.csv' } | ForEach-Object {
        [pscustomobject]@{ RelativePath = $_.FullName.Substring($Root.Length).TrimStart('\'); Length = $_.Length
                           SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash }
    }
    $m = Join-Path $Root 'manifest.csv'
    $rows | Export-Csv -LiteralPath $m -NoTypeInformation -Encoding UTF8
    (Get-FileHash -LiteralPath $m -Algorithm SHA256).Hash
}

function Test-Manifest([string]$Root) {
    $m = Join-Path $Root 'manifest.csv'
    if (-not (Test-Path -LiteralPath $m)) { Write-Bad ('No manifest.csv in {0}' -f $Root); return }
    Write-Info ('manifest.csv SHA256: {0}  (compare with the value you wrote down)' -f (Get-FileHash -LiteralPath $m -Algorithm SHA256).Hash)
    $bad = 0; $listed = @{}
    foreach ($row in @(Import-Csv -LiteralPath $m)) {
        $listed[$row.RelativePath] = $true
        $p = Join-Path $Root $row.RelativePath
        if (-not (Test-Path -LiteralPath $p)) { Write-Bad ('MISSING  {0}' -f $row.RelativePath); $bad++; continue }
        if ((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash -ne $row.SHA256) { Write-Bad ('CHANGED  {0}' -f $row.RelativePath); $bad++ }
    }
    foreach ($f in @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force | Where-Object { $_.Name -ne 'manifest.csv' })) {
        $rel = $f.FullName.Substring($Root.Length).TrimStart('\')
        if (-not $listed.ContainsKey($rel)) { Write-Bad ('EXTRA    {0}' -f $rel); $bad++ }
    }
    if ($bad -eq 0) { Write-Good 'Backup matches its manifest.' } else { Write-Bad ('{0} problems found.' -f $bad) }
}

function Write-RestoreNotes([string]$Root) {
    $lines = @(
        'RESTORE CHEAT SHEET',
        '',
        'DNS zone (zone deleted):',
        '  copy dns\<zone>.dns C:\Windows\System32\dns\',
        '  dnscmd /zoneadd <zone> /primary /file <zone>.dns /load',
        '  dnscmd /zoneresettype <zone> /dsprimary          (make it AD-integrated again)',
        'DNS records (zone tampered): compare dns\<zone>.records.csv with Get-DnsServerResourceRecord and',
        '  fix single records with Add-DnsServerResourceRecordA / Remove-DnsServerResourceRecord.',
        '',
        'GPO:  Restore-GPO -Name "<GPO name>" -Path <backup>\ad\GPO',
        'AD object deleted: Recycle Bin on -> Get-ADObject -Filter ''isDeleted -eq $true'' -IncludeDeletedObjects | Restore-ADObject',
        '                   Recycle Bin off -> recreate from ad\users.csv / ad\group-membership.csv',
        'AD ACL: ad\acl-sddl.csv holds the original SDDL of each sensitive object (compare with (Get-Acl "AD:<dn>").Sddl).',
        'SYSVOL scripts/policies: copy back from ad\SYSVOL.',
        '',
        'IIS config: appcmd restore backup <name>   (name is the folder under web\iis-config)',
        'Site files: robocopy web\content\<site> <physical path> /E',
        '',
        'SQL Server: RESTORE DATABASE [db] FROM DISK = N''<path>.bak'' WITH REPLACE',
        'MySQL:      mysql -u root -p < databases\mysql\all-databases-<time>.sql',
        'PostgreSQL: psql -U postgres -f databases\postgres\pg_dumpall-<time>.sql',
        '',
        'Firewall:   netsh advfirewall import firewall\firewall.wfw',
        '',
        'Integrity:  .\backup-all.ps1 -Verify <this folder>'
    )
    $lines | Set-Content -LiteralPath (Join-Path $Root 'RESTORE.txt') -Encoding UTF8
}

# ---------------------------------------------------------------- main
if ($MyInvocation.InvocationName -eq '.') { return }
if (-not (Test-IsAdmin)) { Write-Bad 'Run this from an elevated PowerShell.'; exit 1 }

if ($Verify) { Write-Section ('Verifying {0}' -f $Verify); Test-Manifest -Root (Resolve-Path -LiteralPath $Verify).ProviderPath; return }

New-Item -ItemType Directory -Path $Destination -Force | Out-Null
Protect-Folder $Destination
$root = Join-Path $Destination ('backup-{0}-{1}' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $root -Force | Out-Null
try { Start-Transcript -Path (Join-Path $root 'transcript.txt') -Force | Out-Null } catch { }

try {
    Write-Section ('Backing up {0} to {1}' -f $env:COMPUTERNAME, $root)
    if (-not $SkipDns) { try { Backup-Dns $root } catch { Add-Result 'DNS' 'FAILED' $_.Exception.Message } }
    if (-not $SkipAD) { try { Backup-AD $root } catch { Add-Result 'Active Directory' 'FAILED' $_.Exception.Message } }
    if (-not $SkipWeb) { try { Backup-Web $root } catch { Add-Result 'Web' 'FAILED' $_.Exception.Message } }
    if (-not $SkipDatabases) {
        try { Backup-SqlServer $root } catch { Add-Result 'SQL Server' 'FAILED' $_.Exception.Message }
        try { Backup-MySql $root } catch { Add-Result 'MySQL/MariaDB' 'FAILED' $_.Exception.Message }
        try { Backup-Postgres $root } catch { Add-Result 'PostgreSQL' 'FAILED' $_.Exception.Message }
    }
    try {
        $fwDir = Join-Path $root 'firewall'
        New-Item -ItemType Directory -Path $fwDir -Force | Out-Null
        & netsh.exe advfirewall export (Join-Path $fwDir 'firewall.wfw') | Out-Null
        Add-Result 'Firewall' 'OK' (Join-Path $fwDir 'firewall.wfw')
    } catch { Add-Result 'Firewall' 'FAILED' $_.Exception.Message }

    Write-RestoreNotes $root
} finally {
    try { Stop-Transcript | Out-Null } catch { }
}

$script:Results | Export-Csv -LiteralPath (Join-Path $root 'summary.csv') -NoTypeInformation -Encoding UTF8   # before the manifest so -Verify covers it

Write-Section 'Manifest'
$mhash = Write-Manifest $root
Write-Good ('manifest.csv SHA256: {0}' -f $mhash)
Write-Warn 'Write that hash on paper. -Verify uses it to prove the backup was not altered.'

if ($Zip) {
    try {
        Compress-Archive -Path (Join-Path $root '*') -DestinationPath ('{0}.zip' -f $root) -CompressionLevel Optimal -Force
        Write-Good ('Zipped: {0}.zip' -f $root)
    } catch { Write-Bad ('Zip failed: {0}' -f $_.Exception.Message) }
}
if ($CopyTo) {
    $dest = Join-Path $CopyTo (Split-Path -Leaf $root)
    if (Invoke-Robocopy $root $dest) { Write-Good ('Copied to {0}' -f $dest) } else { Write-Bad ('Copy to {0} had errors' -f $dest) }
    if ($Zip -and (Test-Path -LiteralPath ('{0}.zip' -f $root))) { Copy-Item -LiteralPath ('{0}.zip' -f $root) -Destination $CopyTo -Force }
}

Write-Section 'Summary'
foreach ($r in $script:Results) { Write-Info ('{0,-18} {1,-8} {2}' -f $r.Component, $r.Status, $r.Detail) }
Write-Info ('Backup folder: {0}  (see RESTORE.txt)' -f $root)
