<#
.SYNOPSIS
    Proves sfc.exe is genuine before trusting it, restores a known-good copy if it is not, then runs sfc.

.DESCRIPTION
    Red team can replace or hijack sfc.exe so "sfc /scannow" reports a clean box. This script:
      1. Shows what actually runs when someone types "sfc" (PATH, alias and current-folder hijacks).
      2. Checks Image File Execution Options / SilentProcessExit hijacks on sfc and the servicing engine.
      3. Checks the TrustedInstaller (Windows Modules Installer) service that sfc depends on.
      4. Verifies each target file: Microsoft signature chaining to a Microsoft root, the right original
         filename (catches cmd.exe renamed to sfc.exe), a real PE header, and optional kit SHA256 list.
      5. Replaces a bad file from, in order: your -Kit folder, this machine's WinSxS store, or (with
         -Online) Microsoft's public symbol server using Winbindex hash data. The bad file is
         quarantined as evidence, never deleted, and ownership goes back to TrustedInstaller.
      6. Runs sfc /scannow (or /verifyonly) by full path and summarizes the [SR] lines from CBS.log.

    The same repair works for other System32 binaries, e.g. sticky-keys backdoors:
        .\sfc-repair.ps1 -Files sethc.exe,utilman.exe -NoScan

.PARAMETER Files       System32 file names to verify/repair. Default: sfc.exe, sfc_os.dll.
.PARAMETER Kit         Folder of known-good copies made with -BuildKit on a clean VM of the same build.
.PARAMETER BuildKit    On a CLEAN VM: copy targets + common backdoor targets into -Kit and record hashes.
.PARAMETER Online      Allow downloading a known-good binary from Microsoft's symbol server.
.PARAMETER RunDism     If nothing good is found locally, run DISM /RestoreHealth and retry WinSxS.
.PARAMETER ScanOnly    Run sfc /verifyonly instead of /scannow.
.PARAMETER NoScan      Verify and repair files but do not run sfc.
.PARAMETER OutDir      Root for reports and quarantine. Default C:\Backup.

.EXAMPLE
    .\sfc-repair.ps1
.EXAMPLE
    .\sfc-repair.ps1 -Kit E:\kit -Online -Confirm:$false
.EXAMPLE
    .\sfc-repair.ps1 -BuildKit -Kit E:\kit      # night before, on a clean VM
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string[]]$Files = @('sfc.exe', 'sfc_os.dll'),
    [string]$Kit,
    [switch]$BuildKit,
    [switch]$Online,
    [switch]$RunDism,
    [switch]$ScanOnly,
    [switch]$NoScan,
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

# Self-signed Microsoft roots that Windows binaries chain to (SHA1 thumbprints).
$script:MicrosoftRoots = @{
    'CDD4EEAE6000AC7F40C3802C171E30148030C072' = 'Microsoft Root Certificate Authority'
    '3B1EFD3A66EA28B16697394703A72CA340A05BD5' = 'Microsoft Root Certificate Authority 2010'
    '8F43288AD272F3103B6FB1428485EA3014C0BCFE' = 'Microsoft Root Certificate Authority 2011'
    'A43489159A520F0D93D032CCAF37E7FE20A8B419' = 'Microsoft Root Authority'
}
$script:BackdoorTargets = @('sfc.exe', 'sfc_os.dll', 'sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe',
                            'Narrator.exe', 'DisplaySwitch.exe', 'AtBroker.exe', 'cmd.exe')
# Binaries swapped in for accessibility tools / sfc. If a target's OriginalFilename is one of these
# (and the target is not that file), it is a renamed shell = backdoor.
$script:ShellNames = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'explorer.exe', 'taskmgr.exe', 'regedit.exe', 'mmc.exe',
                       'conhost.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'notepad.exe', 'regsvr32.exe')

function Get-OsBuild {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    # Win10 21H2/22H2 (19044/19045) and Win11 23H2 (22631) ship binaries versioned with the base build
    # (19041 / 22621), so also read the build stamped on ntdll.dll.
    $binBuild = [string]$cv.CurrentBuild
    try { $binBuild = [string](Get-Item -LiteralPath (Join-Path $env:windir 'System32\ntdll.dll')).VersionInfo.FileBuildPart } catch { }
    [pscustomobject]@{
        Build    = [string]$cv.CurrentBuild
        BinBuild = $binBuild
        UBR      = [int]$cv.UBR
        Product  = [string]$cv.ProductName
        Label    = ('{0}.{1}' -f $cv.CurrentBuild, $cv.UBR)
    }
}

function Get-BuildPattern($Os) {
    $builds = @($Os.Build, $Os.BinBuild) | Where-Object { $_ } | Select-Object -Unique
    '^\s*\d+\.\d+\.(' + ($builds -join '|') + ')\.'
}

function Get-VersionRevision([string]$Version) {
    # "10.0.17763.1 (WinBuild.160101.0800)" -> 1
    if ($Version -match '^\s*\d+\.\d+\.\d+\.(\d+)') { return [int]$Matches[1] }
    return -1
}

function Test-PEHeader([string]$Path) {
    try {
        $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            $b = New-Object byte[] 2
            if ($fs.Read($b, 0, 2) -ne 2) { return $false }
            return ($b[0] -eq 0x4D -and $b[1] -eq 0x5A)
        } finally { $fs.Dispose() }
    } catch { return $false }
}

function Get-ChainRoot($Cert) {
    # Returns the top of the chain and whether it is a real self-signed root (a partial chain is "unknown").
    try {
        $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        [void]$chain.Build($Cert)
        $n = $chain.ChainElements.Count
        if ($n -gt 0) {
            $top = $chain.ChainElements[$n - 1].Certificate
            return [pscustomobject]@{ Thumbprint = $top.Thumbprint; SelfSigned = ($top.Subject -eq $top.Issuer) }
        }
    } catch { }
    return $null
}

function Test-SystemBinary {
    param([string]$Path, [string]$ExpectedName, [hashtable]$TrustedHashes)
    $r = [ordered]@{
        Path = $Path; Exists = $false; SHA256 = $null; Signature = $null; Signer = $null
        OriginalName = $null; Version = $null; IsPE = $false; HashTrusted = $false; Good = $false; Reasons = @()
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $r.Reasons += 'file is missing'
        return [pscustomobject]$r
    }
    $r.Exists = $true
    try { $r.SHA256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $r.Reasons += 'could not hash file' }
    $r.IsPE = Test-PEHeader $Path
    if (-not $r.IsPE) { $r.Reasons += 'no MZ header (not a real executable)' }
    try {
        $vi = (Get-Item -LiteralPath $Path -ErrorAction Stop).VersionInfo
        $r.OriginalName = $vi.OriginalFilename
        $r.Version = $vi.FileVersion
    } catch { }
    # Fail only when the file is really a shell renamed to the target (cmd.exe -> sethc.exe).
    # Some genuine binaries carry a different internal name, so other mismatches are just noted.
    $nameOk = $true
    $orig = ''
    if ($r.OriginalName) { $orig = (($r.OriginalName -replace '\.mui$', '').Trim()) }
    if ($orig -and $orig -ine $ExpectedName) {
        if ($script:ShellNames -contains $orig.ToLowerInvariant()) {
            $nameOk = $false
            $r.Reasons += ("file is really '{0}' renamed to '{1}' (backdoor)" -f $orig, $ExpectedName)
        } else {
            $r.Reasons += ("note: original filename '{0}'" -f $orig)
        }
    }

    $sigOk = $false
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $r.Signature = [string]$sig.Status
        if ($sig.SignerCertificate) { $r.Signer = $sig.SignerCertificate.Subject }
        $sigOk = ($sig.Status -eq 'Valid') -and ($r.Signer -match 'O=Microsoft Corporation')
        if ($sigOk) {
            $root = Get-ChainRoot $sig.SignerCertificate
            if ($root -and $root.SelfSigned -and -not $script:MicrosoftRoots.ContainsKey($root.Thumbprint)) {
                $sigOk = $false
                $r.Reasons += ('"Microsoft" signature chains to non-Microsoft root {0} - planted root CA?' -f $root.Thumbprint)
            }
        } else {
            $r.Reasons += ('signature {0} {1}' -f $r.Signature, $r.Signer)
        }
    } catch { $r.Reasons += 'could not read signature' }

    if ($TrustedHashes -and $r.SHA256 -and $TrustedHashes.ContainsKey($r.SHA256)) { $r.HashTrusted = $true }
    $r.Good = $r.IsPE -and $nameOk -and ($sigOk -or $r.HashTrusted)
    [pscustomobject]$r
}

function Select-BestCandidate {
    param([object[]]$Tested, $Os)
    $pattern = Get-BuildPattern $Os
    $good = @($Tested | Where-Object { $_.Good -and ([string]$_.Version -match $pattern) })
    if ($good.Count -eq 0) { return $null }
    $notNewer = @($good | Where-Object { (Get-VersionRevision $_.Version) -le $Os.UBR })
    $pool = $good
    if ($notNewer.Count -gt 0) { $pool = $notNewer }
    $pool | Sort-Object -Property @{ Expression = { Get-VersionRevision $_.Version } } -Descending | Select-Object -First 1
}

function Get-KitHashes([string]$KitPath) {
    $h = @{}
    if (-not $KitPath) { return $h }
    $csv = Join-Path $KitPath 'hashes.csv'
    if (Test-Path -LiteralPath $csv) {
        foreach ($row in Import-Csv -LiteralPath $csv) { if ($row.SHA256) { $h[$row.SHA256.ToUpperInvariant()] = $row } }
    }
    $h
}

function Find-KitCopies([string]$KitPath, [string]$FileName) {
    $found = @()
    $direct = Join-Path $KitPath $FileName
    if (Test-Path -LiteralPath $direct) { $found += $direct }
    foreach ($d in @(Get-ChildItem -LiteralPath $KitPath -Directory -ErrorAction SilentlyContinue)) {
        $p = Join-Path $d.FullName $FileName
        if (Test-Path -LiteralPath $p) { $found += $p }
    }
    $found
}

function Find-WinSxSCopies([string]$FileName) {
    $sxs = Join-Path $env:windir 'WinSxS'
    $prefix = 'amd64_*'
    if (-not [Environment]::Is64BitOperatingSystem) { $prefix = 'x86_*' }
    $found = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($d in [IO.Directory]::EnumerateDirectories($sxs, $prefix)) {
            $f = [IO.Path]::Combine($d, $FileName)
            if ([IO.File]::Exists($f)) { $found.Add($f) }
        }
    } catch { Write-Warn ('Could not enumerate WinSxS: {0}' -f $_.Exception.Message) }
    $found.ToArray()
}

function Get-WinbindexCandidates([string]$FileName, [string]$BuildPattern) {
    $url = 'https://winbindex.m417z.com/data/by_filename_compressed/{0}.json.gz' -f $FileName.ToLowerInvariant()
    $gzPath = Join-Path $env:TEMP ('winbindex-{0}.json.gz' -f $FileName)
    Invoke-WebRequest -Uri $url -OutFile $gzPath -UseBasicParsing -ErrorAction Stop
    $fs = [IO.File]::OpenRead($gzPath)
    try {
        $gz = New-Object IO.Compression.GZipStream($fs, [IO.Compression.CompressionMode]::Decompress)
        $sr = New-Object IO.StreamReader($gz)
        $json = $sr.ReadToEnd()
    } finally { $fs.Dispose() }
    $data = $json | ConvertFrom-Json
    foreach ($p in $data.PSObject.Properties) {
        $fi = $p.Value.fileInfo
        if (-not $fi) { continue }
        if ($fi.machineType -ne 34404) { continue }          # 0x8664 = x64
        if (-not $fi.timestamp -or -not $fi.virtualSize) { continue }
        if ([string]$fi.version -notmatch $BuildPattern) { continue }
        $sha = [string]$p.Name
        if ($fi.sha256) { $sha = [string]$fi.sha256 }
        [pscustomobject]@{ SHA256 = $sha.ToUpperInvariant(); Version = [string]$fi.version
                           Timestamp = [int64]$fi.timestamp; VirtualSize = [int64]$fi.virtualSize }
    }
}

function Get-SymbolServerCopy($Candidate, [string]$FileName) {
    $id = '{0:X8}{1:x}' -f $Candidate.Timestamp, $Candidate.VirtualSize
    $url = 'https://msdl.microsoft.com/download/symbols/{0}/{1}/{0}' -f $FileName, $id
    $dir = Join-Path $env:TEMP ('msdl-{0}' -f $Candidate.SHA256.Substring(0, 12))
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $out = Join-Path $dir $FileName
    Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing -ErrorAction Stop
    $h = (Get-FileHash -LiteralPath $out -Algorithm SHA256).Hash
    if ($h -ne $Candidate.SHA256) { Remove-Item -LiteralPath $out -Force; throw ('hash mismatch on download ({0})' -f $h) }
    $out
}

function Find-GoodCopy {
    param([string]$Name, $Os, [hashtable]$Trusted)
    if ($Kit) {
        Write-Info ('Looking in kit {0}' -f $Kit)
        $tested = @(Find-KitCopies -KitPath $Kit -FileName $Name | ForEach-Object { Test-SystemBinary -Path $_ -ExpectedName $Name -TrustedHashes $Trusted })
        $best = Select-BestCandidate -Tested $tested -Os $Os
        if ($best) { Write-Good ('Kit copy verified: {0}' -f $best.Path); return $best }
    }
    Write-Info 'Looking in the WinSxS component store'
    $tested = @(Find-WinSxSCopies -FileName $Name | ForEach-Object { Test-SystemBinary -Path $_ -ExpectedName $Name -TrustedHashes $Trusted })
    Write-Info ('  {0} copies found, {1} verified' -f $tested.Count, @($tested | Where-Object { $_.Good }).Count)
    $best = Select-BestCandidate -Tested $tested -Os $Os
    if ($best) { Write-Good ('WinSxS copy verified: {0}' -f $best.Path); return $best }

    if ($Online) {
        Write-Info 'Looking up Microsoft-published hashes (Winbindex) and the Microsoft symbol server'
        try {
            $cands = @(Get-WinbindexCandidates -FileName $Name -BuildPattern (Get-BuildPattern $Os))
            Write-Info ('  {0} published versions for build {1}' -f $cands.Count, $Os.BinBuild)
            $ordered = @($cands | Sort-Object -Descending -Property `
                @{ Expression = { if ((Get-VersionRevision $_.Version) -le $Os.UBR) { 1 } else { 0 } } },
                @{ Expression = { Get-VersionRevision $_.Version } })
            foreach ($c in ($ordered | Select-Object -First 5)) {
                try {
                    $dl = Get-SymbolServerCopy -Candidate $c -FileName $Name
                    $h = @{}
                    foreach ($k in $Trusted.Keys) { $h[$k] = $Trusted[$k] }
                    $h[$c.SHA256] = 'winbindex'
                    $t = Test-SystemBinary -Path $dl -ExpectedName $Name -TrustedHashes $h
                    if ($t.Good) { Write-Good ('Downloaded and verified {0} {1}' -f $Name, $c.Version); return $t }
                } catch { Write-Warn ('  {0}: {1}' -f $c.Version, $_.Exception.Message) }
            }
        } catch { Write-Warn ('Online lookup failed: {0}' -f $_.Exception.Message) }
    }
    return $null
}

function Set-SystemFileAcl([string]$Target) {
    # Copy the DACL of an untouched System32 binary, then hand ownership back to TrustedInstaller.
    $ref = Join-Path $env:windir 'System32\find.exe'
    $done = $false
    try {
        $sections = [Security.AccessControl.AccessControlSections]::Access
        $sddl = (Get-Acl -LiteralPath $ref).GetSecurityDescriptorSddlForm($sections)
        $sec = New-Object Security.AccessControl.FileSecurity
        $sec.SetSecurityDescriptorSddlForm($sddl, $sections)
        Set-Acl -LiteralPath $Target -AclObject $sec -ErrorAction Stop
        $done = $true
    } catch { }
    if (-not $done) {
        & icacls.exe $Target /inheritance:r /grant:r 'NT SERVICE\TrustedInstaller:F' '*S-1-5-32-544:RX' '*S-1-5-18:RX' '*S-1-5-32-545:RX' | Out-Null
    }
    & icacls.exe $Target /setowner 'NT SERVICE\TrustedInstaller' | Out-Null
}

function Restore-SystemBinary {
    param([string]$Target, [string]$Source, [string]$QuarantineDir)
    $name = [IO.Path]::GetFileName($Target)
    if ($PSCmdlet -and -not $PSCmdlet.ShouldProcess($Target, ('Replace with verified copy from {0}' -f $Source))) { return $false }
    New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $staged = Join-Path $env:TEMP ('{0}.{1}.good' -f $name, $stamp)
    Copy-Item -LiteralPath $Source -Destination $staged -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $Target) {
        & takeown.exe /F $Target /A | Out-Null
        & icacls.exe $Target /grant '*S-1-5-32-544:F' | Out-Null
        $q = Join-Path $QuarantineDir ('{0}.{1}.quarantined' -f $name, $stamp)
        Move-Item -LiteralPath $Target -Destination $q -Force -ErrorAction Stop
        Write-Info ('Quarantined bad copy to {0}' -f $q)
    }
    Copy-Item -LiteralPath $staged -Destination $Target -Force -ErrorAction Stop
    Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
    Set-SystemFileAcl -Target $Target
    return $true
}

function Invoke-BuildKit {
    param([string]$KitPath, [string[]]$Names, $Os)
    $dest = Join-Path $KitPath $Os.Label
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    $csv = Join-Path $KitPath 'hashes.csv'
    $rows = @()
    if (Test-Path -LiteralPath $csv) { $rows = @(Import-Csv -LiteralPath $csv) }
    foreach ($n in $Names) {
        $src = Join-Path $env:windir ('System32\{0}' -f $n)
        $t = Test-SystemBinary -Path $src -ExpectedName $n
        if (-not $t.Good) { Write-Bad ('{0} does not verify on this VM ({1}) - not copied' -f $n, ($t.Reasons -join '; ')); continue }
        Copy-Item -LiteralPath $src -Destination (Join-Path $dest $n) -Force
        $rows += [pscustomobject]@{ Build = $Os.Build; BinBuild = $Os.BinBuild; UBR = $Os.UBR; Product = $Os.Product; FileName = $n; Version = $t.Version; SHA256 = $t.SHA256 }
        Write-Good ('{0,-18} {1,-40} {2}' -f $n, $t.Version, $t.SHA256)
    }
    $rows | Sort-Object FileName, Build, UBR, SHA256 -Unique | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
    Write-Good ('Kit written to {0} (hashes in {1})' -f $dest, $csv)
}

function Get-ExecHijacks([string[]]$Names) {
    $roots = @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
               'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')
    foreach ($n in $Names) {
        foreach ($root in $roots) {
            $k = Join-Path $root $n
            if (-not (Test-Path -LiteralPath $k)) { continue }
            $p = Get-ItemProperty -LiteralPath $k
            if ($p.Debugger) { [pscustomobject]@{ Name = $n; Key = $k; Value = 'Debugger'; Data = [string]$p.Debugger } }
            if ($p.GlobalFlag -and (([int]$p.GlobalFlag -band 0x200) -ne 0)) {
                [pscustomobject]@{ Name = $n; Key = $k; Value = 'GlobalFlag'; Data = ('0x{0:X}' -f [int]$p.GlobalFlag) }
            }
        }
        $spe = Join-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' $n
        if (Test-Path -LiteralPath $spe) {
            $p = Get-ItemProperty -LiteralPath $spe
            if ($p.MonitorProcess) { [pscustomobject]@{ Name = $n; Key = $spe; Value = 'MonitorProcess'; Data = [string]$p.MonitorProcess } }
        }
    }
}

function Show-CommandResolution {
    $expected = Join-Path $env:windir 'System32\sfc.exe'
    $hits = @(Get-Command -Name 'sfc' -All -ErrorAction SilentlyContinue)
    foreach ($h in $hits) {
        $where = $h.Source
        if (-not $where) { $where = $h.Definition }
        Write-Info ('{0,-12} {1}' -f $h.CommandType, $where)
    }
    if ($hits.Count -eq 0) { Write-Bad 'Nothing named sfc resolves from PATH.' }
    elseif ($hits[0].CommandType -ne 'Application' -or ($hits[0].Source -ine $expected)) {
        Write-Bad ('Typing "sfc" runs {0} {1}, not {2}. Remove it.' -f $hits[0].CommandType, $hits[0].Source, $expected)
    } else { Write-Good 'Typing "sfc" resolves to System32\sfc.exe first.' }
    foreach ($ext in @('.exe', '.com', '.bat', '.cmd', '.vbs', '.js')) {
        $p = Join-Path (Get-Location).ProviderPath ('sfc{0}' -f $ext)
        if ((Test-Path -LiteralPath $p) -and ($p -ine $expected)) { Write-Bad ('cmd.exe would run {0} from the current folder first.' -f $p) }
    }
}

function Test-TrustedInstallerService {
    $svc = Get-CimInstance Win32_Service -Filter "Name='TrustedInstaller'" -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Bad 'TrustedInstaller service is missing - sfc cannot repair anything.'; return }
    $expected = Join-Path $env:windir 'servicing\TrustedInstaller.exe'
    $path = ([Environment]::ExpandEnvironmentVariables([string]$svc.PathName)).Trim().Trim('"')
    if ($path -ine $expected) { Write-Bad ("TrustedInstaller binary path is '{0}' (expected {1})" -f $path, $expected) }
    else { Write-Good 'TrustedInstaller binary path is correct.' }
    $t = Test-SystemBinary -Path $expected -ExpectedName 'TrustedInstaller.exe'
    if ($t.Good) { Write-Good 'TrustedInstaller.exe verifies.' } else { Write-Bad ('TrustedInstaller.exe failed: {0}' -f ($t.Reasons -join '; ')) }
    if ($svc.StartMode -eq 'Disabled') {
        Write-Bad 'TrustedInstaller is Disabled - sfc will fail.'
        if ($PSCmdlet -and $PSCmdlet.ShouldProcess('TrustedInstaller', 'Set start type to Manual')) {
            Set-Service -Name TrustedInstaller -StartupType Manual
            Write-Good 'Set to Manual.'
        }
    } else { Write-Good ('TrustedInstaller start type: {0}' -f $svc.StartMode) }
}

function Get-SfcSummary([datetime]$Since) {
    $cbs = Join-Path $env:windir 'Logs\CBS\CBS.log'
    $out = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $cbs)) { return $out.ToArray() }
    try {
        $fs = [IO.File]::Open($cbs, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $sr = New-Object IO.StreamReader($fs)
        try {
            while (-not $sr.EndOfStream) {
                $line = $sr.ReadLine()
                if ($line.IndexOf('[SR]') -lt 0) { continue }
                if ($line.Length -ge 19) {
                    $ts = [datetime]::MinValue
                    if ([datetime]::TryParseExact($line.Substring(0, 19), 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$ts)) {
                        if ($ts -lt $Since) { continue }
                    }
                }
                $out.Add($line)
            }
        } finally { $sr.Dispose(); $fs.Dispose() }
    } catch { Write-Warn ('Could not read CBS.log: {0}' -f $_.Exception.Message) }
    $out.ToArray()
}

# ---------------------------------------------------------------- main
if ($MyInvocation.InvocationName -eq '.') { return }

if (-not (Test-IsAdmin)) { Write-Bad 'Run this from an elevated PowerShell.'; exit 1 }
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    Write-Bad 'Run from 64-bit PowerShell (32-bit PowerShell sees a redirected System32).'; exit 1
}
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$os = Get-OsBuild
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportDir = Join-Path $OutDir ('reports\sfc-repair-{0}' -f $stamp)
$quarantine = Join-Path $OutDir 'quarantine'
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
try { Start-Transcript -Path (Join-Path $reportDir 'transcript.txt') -Force | Out-Null } catch { }

try {
    Write-Section ('sfc-repair on {0} ({1}, build {2})' -f $env:COMPUTERNAME, $os.Product, $os.Label)

    if ($BuildKit) {
        if (-not $Kit) { Write-Bad '-BuildKit needs -Kit <folder>.'; return }
        Invoke-BuildKit -KitPath $Kit -Names (@($Files) + $script:BackdoorTargets | Select-Object -Unique) -Os $os
        return
    }

    $trusted = Get-KitHashes $Kit

    Write-Section 'What runs when you type sfc'
    Show-CommandResolution

    Write-Section 'Execution hijacks (IFEO / SilentProcessExit)'
    $hijackNames = @($Files) + @('sfc.exe', 'TrustedInstaller.exe', 'TiWorker.exe', 'dism.exe') | Select-Object -Unique
    $hijacks = @(Get-ExecHijacks -Names $hijackNames)
    if ($hijacks.Count -eq 0) { Write-Good 'No hijacks found.' }
    foreach ($h in $hijacks) {
        Write-Bad ('{0}: {1} = {2}  ({3})' -f $h.Name, $h.Value, $h.Data, $h.Key)
        if ($PSCmdlet.ShouldProcess($h.Key, ('Remove value {0}' -f $h.Value))) {
            Remove-ItemProperty -LiteralPath $h.Key -Name $h.Value -ErrorAction SilentlyContinue
            Write-Good ('Removed {0}' -f $h.Value)
        }
    }

    Write-Section 'TrustedInstaller service'
    Test-TrustedInstallerService

    Write-Section 'Verify and repair files'
    $results = @()
    foreach ($name in $Files) {
        $target = Join-Path $env:windir ('System32\{0}' -f $name)
        $t = Test-SystemBinary -Path $target -ExpectedName $name -TrustedHashes $trusted
        if ($t.Good) {
            Write-Good ('{0} OK  {1}  {2}' -f $name, $t.Version, $t.SHA256)
            $results += [pscustomobject]@{ File = $name; Status = 'OK'; Version = $t.Version; SHA256 = $t.SHA256; Detail = ($t.Reasons -join '; ') }
            continue
        }
        Write-Bad ('{0} FAILED: {1}' -f $name, ($t.Reasons -join '; '))
        $src = Find-GoodCopy -Name $name -Os $os -Trusted $trusted
        if (-not $src -and $RunDism) {
            Write-Info 'Running DISM /Online /Cleanup-Image /RestoreHealth (10-30 minutes)...'
            & (Join-Path $env:windir 'System32\dism.exe') /Online /Cleanup-Image /RestoreHealth
            $src = Find-GoodCopy -Name $name -Os $os -Trusted $trusted
        }
        if (-not $src) {
            Write-Bad ('No verified replacement for {0}. Try -Kit, -Online or -RunDism, or copy one from a clean VM on build {1}.' -f $name, $os.Label)
            $results += [pscustomobject]@{ File = $name; Status = 'BAD - not repaired'; Version = $t.Version; SHA256 = $t.SHA256; Detail = ($t.Reasons -join '; ') }
            continue
        }
        try {
            if (Restore-SystemBinary -Target $target -Source $src.Path -QuarantineDir $quarantine) {
                $after = Test-SystemBinary -Path $target -ExpectedName $name -TrustedHashes $trusted
                if (-not $after.Good -and $after.SHA256 -eq $src.SHA256) { $after.Good = $true }   # online copy: trusted by hash
                if ($after.Good) {
                    Write-Good ('{0} restored ({1})' -f $name, $after.Version)
                    $results += [pscustomobject]@{ File = $name; Status = 'REPAIRED'; Version = $after.Version; SHA256 = $after.SHA256; Detail = ('was: ' + ($t.Reasons -join '; ')) }
                } else {
                    Write-Bad ('{0} still fails after replace: {1}' -f $name, ($after.Reasons -join '; '))
                    $results += [pscustomobject]@{ File = $name; Status = 'REPLACE FAILED'; Version = $after.Version; SHA256 = $after.SHA256; Detail = ($after.Reasons -join '; ') }
                }
            } else {
                $results += [pscustomobject]@{ File = $name; Status = 'BAD - skipped by user'; Version = $t.Version; SHA256 = $t.SHA256; Detail = ($t.Reasons -join '; ') }
            }
        } catch {
            Write-Bad ('Replace failed: {0}' -f $_.Exception.Message)
            $results += [pscustomobject]@{ File = $name; Status = 'REPLACE ERROR'; Version = $t.Version; SHA256 = $t.SHA256; Detail = $_.Exception.Message }
        }
    }
    $results | Export-Csv -LiteralPath (Join-Path $reportDir 'files.csv') -NoTypeInformation -Encoding UTF8

    if (-not $NoScan) {
        $sfcPath = Join-Path $env:windir 'System32\sfc.exe'
        $sfcCheck = $results | Where-Object { $_.File -ieq 'sfc.exe' } | Select-Object -First 1
        $sfcOk = $true
        if ($sfcCheck) { $sfcOk = ($sfcCheck.Status -in 'OK', 'REPAIRED') }
        else { $sfcOk = (Test-SystemBinary -Path $sfcPath -ExpectedName 'sfc.exe' -TrustedHashes $trusted).Good }
        if (-not $sfcOk) {
            Write-Bad 'sfc.exe is not verified - refusing to run it.'
        } else {
            $arg = '/scannow'
            if ($ScanOnly) { $arg = '/verifyonly' }
            Write-Section ('Running {0} {1} (10-20 minutes)' -f $sfcPath, $arg)
            $start = (Get-Date).AddMinutes(-1)
            $proc = Start-Process -FilePath $sfcPath -ArgumentList $arg -NoNewWindow -Wait -PassThru
            Write-Info ('sfc exit code {0}' -f $proc.ExitCode)
            $sr = @(Get-SfcSummary -Since $start)
            $sr | Set-Content -LiteralPath (Join-Path $reportDir 'sfc-SR-lines.txt') -Encoding UTF8
            $cannot = @($sr | Where-Object { $_ -match 'Cannot repair' })
            $repaired = @($sr | Where-Object { $_ -match 'Repairing corrupted file|Repaired file' })
            Write-Info ('CBS.log: {0} [SR] lines, {1} repaired, {2} could not be repaired' -f $sr.Count, $repaired.Count, $cannot.Count)
            foreach ($l in ($cannot + $repaired | Select-Object -First 40)) { Write-Warn $l }
            if ($cannot.Count -gt 0) { Write-Bad 'Some files could not be repaired: run with -RunDism, then sfc again.' }
        }
    }

    Write-Section 'Done'
    Write-Info ('Report: {0}' -f $reportDir)
    if (Test-Path -LiteralPath $quarantine) { Write-Info ('Quarantined originals (evidence): {0}' -f $quarantine) }
} finally {
    try { Stop-Transcript | Out-Null } catch { }
}
