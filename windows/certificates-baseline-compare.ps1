<#
.SYNOPSIS
    Lists certificates that are new since a baseline or not trusted by Microsoft, and flags planted roots.

.DESCRIPTION
    Checks every LocalMachine and CurrentUser certificate store:
      - Root / AuthRoot / CA certs that are NOT in Microsoft's Trusted Root Program list
        (downloaded with "certutil -generateSSTFromWU"; skip with -Offline)
      - Where each trusted root came from: local registry, Group Policy, or AD (Enterprise store)
      - TrustedPublisher / TrustedPeople entries, code-signing certs, recently issued certs
      - On a DC: CAs in the AD NTAuth store that are not one of your enterprise CAs (lets someone
        log in as any user with a forged certificate)
      - Baseline diff: certs added or removed since -SaveBaseline (or since a clean-VM baseline)
    -Remove <thumbprint,...> exports the cert to C:\Backup\quarantine\certs and deletes it.

.EXAMPLE
    .\certificates-baseline-compare.ps1
.EXAMPLE
    .\certificates-baseline-compare.ps1 -SaveBaseline
.EXAMPLE
    .\certificates-baseline-compare.ps1 -Remove 1A2B3C...
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$OutDir = 'C:\Backup',
    [string]$Baseline,
    [switch]$SaveBaseline,
    [switch]$Offline,
    [string[]]$Remove,
    [int]$RecentDays = 30,
    [int]$MinScore = 2
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

$script:TrustStores = @('Root', 'AuthRoot', 'CA', 'TrustedPublisher', 'TrustedPeople', 'SmartCardRoot', 'NTAuth')
# Legacy roots and test certs that ship in default Windows stores but are not all in the downloaded
# root-program list. Without this they show up as false positives on every box.
$script:BuiltinLegacy = @{
    'CDD4EEAE6000AC7F40C3802C171E30148030C072' = 'Microsoft Root Certificate Authority'
    '3B1EFD3A66EA28B16697394703A72CA340A05BD5' = 'Microsoft Root Certificate Authority 2010'
    '8F43288AD272F3103B6FB1428485EA3014C0BCFE' = 'Microsoft Root Certificate Authority 2011'
    'A43489159A520F0D93D032CCAF37E7FE20A8B419' = 'Microsoft Root Authority'
    '245C97DF7514E7CF2DF8BE72AE957B9E04741E85' = 'Copyright (c) 1997 Microsoft Corp.'
    '7F88CD7223F3C813818C994614A89C99FA3B5247' = 'Microsoft Authenticode(tm) Root Authority'
    '18F7C1FCC3090203FD5BAA2F861A754976C8DD25' = 'NO LIABILITY ACCEPTED, (c)97 VeriSign, Inc.'
    'BE36A4562FB2EE05DBB3D32323ADF445084ED656' = 'Thawte Timestamping CA'
    'FEE449EE0E3965A5246F000E87FDE2A065FD89D4' = 'Root Agency (default CA-store test cert)'
}

function Test-OwnMachineCert($C) {
    # The DC's own auto-enrolled certs (Kerberos Authentication, Domain Controller) are expected.
    if ($C.Location -ne 'LocalMachine') { return $false }
    $me = [regex]::Escape($env:COMPUTERNAME)
    ($C.Subject -match ('(^|=)' + $me + '(\.|,|$)')) -or ($C.Names -match ('(^|,)' + $me + '(\.|,|$)'))
}

function Get-AllCerts {
    foreach ($loc in 'LocalMachine', 'CurrentUser') {
        foreach ($store in @(Get-ChildItem -Path ('Cert:\{0}' -f $loc) -ErrorAction SilentlyContinue)) {
            try { $items = @(Get-ChildItem -Path ('Cert:\{0}\{1}' -f $loc, $store.Name) -ErrorAction Stop) } catch { continue }
            foreach ($c in $items) {
                if ($c -isnot [Security.Cryptography.X509Certificates.X509Certificate2]) { continue }
                $eku = ''
                try { $eku = (@($c.EnhancedKeyUsageList | ForEach-Object { $_.FriendlyName }) -join ', ') } catch { }
                $names = ''
                try { $names = (@($c.DnsNameList | ForEach-Object { [string]$_ }) -join ',') } catch { }
                [pscustomobject]@{
                    Location = $loc; Store = $store.Name; Thumbprint = $c.Thumbprint; Subject = $c.Subject; Issuer = $c.Issuer; Names = $names
                    NotBefore = $c.NotBefore; NotAfter = $c.NotAfter; HasPrivateKey = $c.HasPrivateKey
                    SelfSigned = ($c.Subject -eq $c.Issuer); EKU = $eku; Source = ''; Score = 0; Reasons = ''; Baseline = ''
                }
            }
        }
    }
}

function Get-MicrosoftTrustedRoots {
    $sst = Join-Path $env:TEMP ('ccdc-roots-{0}.sst' -f [guid]::NewGuid())
    $set = @{}
    try {
        & certutil.exe -generateSSTFromWU $sst | Out-Null
        if (-not (Test-Path -LiteralPath $sst)) { return $null }
        try {
            $col = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
            $col.Import($sst)
            foreach ($c in $col) { $set[$c.Thumbprint.ToUpperInvariant()] = $c.Subject }
        } catch { }
        if ($set.Count -eq 0) {
            foreach ($line in @(& certutil.exe -dump $sst)) {
                if ($line -match 'Cert Hash\(sha1\):\s*([0-9a-fA-F ]+)$') { $set[($Matches[1] -replace ' ', '').ToUpperInvariant()] = '' }
            }
        }
    } finally { Remove-Item -LiteralPath $sst -Force -ErrorAction SilentlyContinue }
    if ($set.Count -eq 0) { return $null }
    $set
}

function Get-RegistryThumbprints([string]$Path) {
    $h = @{}
    if (Test-Path -LiteralPath $Path) {
        foreach ($k in @(Get-ChildItem -LiteralPath $Path -ErrorAction SilentlyContinue)) { $h[$k.PSChildName.ToUpperInvariant()] = $true }
    }
    $h
}

function Get-NTAuthFindings {
    $out = @()
    try { Import-Module ActiveDirectory -ErrorAction Stop } catch { return $out }
    try {
        $config = (Get-ADRootDSE).configurationNamingContext
        $pks = 'CN=Public Key Services,CN=Services,{0}' -f $config
        $enterpriseCAs = @{}
        foreach ($es in @(Get-ADObject -SearchBase ('CN=Enrollment Services,{0}' -f $pks) -Filter * -Properties cACertificate -ErrorAction SilentlyContinue)) {
            foreach ($bytes in @($es.cACertificate)) {
                $c = New-Object Security.Cryptography.X509Certificates.X509Certificate2(, [byte[]]$bytes)
                $enterpriseCAs[$c.Thumbprint] = $c.Subject
            }
        }
        $nt = Get-ADObject -Identity ('CN=NTAuthCertificates,{0}' -f $pks) -Properties cACertificate -ErrorAction Stop
        foreach ($bytes in @($nt.cACertificate)) {
            $c = New-Object Security.Cryptography.X509Certificates.X509Certificate2(, [byte[]]$bytes)
            $known = $enterpriseCAs.ContainsKey($c.Thumbprint)
            $out += [pscustomobject]@{ Thumbprint = $c.Thumbprint; Subject = $c.Subject; NotAfter = $c.NotAfter; IsEnterpriseCA = $known }
        }
    } catch { }
    $out
}

function Set-CertScore($C, [hashtable]$MsRoots, [hashtable]$Enterprise, [hashtable]$Gpo, [hashtable]$LocalReg) {
    $score = 0; $why = @()
    $tp = $C.Thumbprint.ToUpperInvariant()
    if ($Gpo.ContainsKey($tp)) { $C.Source = 'GroupPolicy' }
    elseif ($Enterprise.ContainsKey($tp)) { $C.Source = 'AD (Enterprise)' }
    elseif ($C.Location -eq 'LocalMachine' -and $LocalReg.ContainsKey($tp)) { $C.Source = 'Local registry' }
    $inMs = $script:BuiltinLegacy.ContainsKey($tp)
    if ($MsRoots -and $MsRoots.ContainsKey($tp)) { $inMs = $true }
    if ($C.Store -in 'Root', 'AuthRoot', 'SmartCardRoot') {
        if ($MsRoots -and -not $inMs) {
            if ($C.Source -eq 'AD (Enterprise)') { $score += 1; $why += 'non-Microsoft root from AD - likely your AD CS root, confirm' }
            else { $score += 4; $why += 'trusted root NOT in Microsoft Trusted Root Program' }
            if ($C.Source -eq 'GroupPolicy') { $score += 1; $why += 'pushed by Group Policy (check GPOs)' }
            if ($C.Location -eq 'CurrentUser') { $why += 'user-level root (affects this user only)' }
        }
    }
    if ($C.Store -eq 'CA' -and $C.SelfSigned -and $MsRoots -and -not $inMs) { $score += 2; $why += 'self-signed cert in intermediate CA store' }
    if ($C.Store -in 'TrustedPublisher', 'TrustedPeople') { $score += 2; $why += ('in {0} (code/people trusted without prompts)' -f $C.Store) }
    if ($C.EKU -match 'Code Signing' -and $C.Store -ne 'My' -and -not ($MsRoots -and $inMs)) { $score += 2; $why += 'code-signing certificate' }
    if ($C.NotBefore -gt (Get-Date).AddDays(-$RecentDays) -and $C.Store -ne 'My') { $score += 1; $why += ('issued in the last {0} days' -f $RecentDays) }
    if ($C.Store -eq 'My' -and $C.HasPrivateKey -and $C.EKU -match 'Client Authentication|Smart Card Logon' -and $C.NotBefore -gt (Get-Date).AddDays(-$RecentDays) -and -not (Test-OwnMachineCert $C)) {
        $score += 2; $why += 'new client-auth cert with private key (certificate logon?)'
    }
    $C.Score = $score
    $C.Reasons = ($why -join '; ')
}

function Remove-CertByThumbprint([string]$Thumbprint, [string]$QuarantineDir) {
    $tp = ($Thumbprint -replace '\s', '').ToUpperInvariant()
    $found = @(Get-ChildItem -Path 'Cert:\LocalMachine', 'Cert:\CurrentUser' -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509Certificate2] -and $_.Thumbprint -eq $tp })
    if ($found.Count -eq 0) { Write-Warn ('{0}: not found in any store' -f $tp); return }
    New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null
    foreach ($c in $found) {
        $psPath = $c.PSPath
        $storeName = Split-Path -Leaf (Split-Path -Parent $psPath)
        $file = Join-Path $QuarantineDir ('{0}-{1}.cer' -f $storeName, $tp)
        Export-Certificate -Cert $c -FilePath $file -Force | Out-Null
        if ($PSCmdlet.ShouldProcess(('{0} ({1})' -f $c.Subject, $psPath), 'Delete certificate')) {
            Remove-Item -LiteralPath $psPath -Force
            Write-Good ('Removed {0} from {1} (copy saved to {2})' -f $c.Subject, $storeName, $file)
        }
    }
    Write-Warn 'If it came from Group Policy or AD it will come back - remove it at the source too.'
}

# ---------------------------------------------------------------- main
if ($MyInvocation.InvocationName -eq '.') { return }
if (-not (Test-IsAdmin)) { Write-Bad 'Run this from an elevated PowerShell.'; exit 1 }
$ProgressPreference = 'SilentlyContinue'

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportDir = Join-Path $OutDir ('reports\certificates-{0}' -f $stamp)
$baselineDir = Join-Path $OutDir 'baselines'
New-Item -ItemType Directory -Path $reportDir, $baselineDir -Force | Out-Null
try { Start-Transcript -Path (Join-Path $reportDir 'transcript.txt') -Force | Out-Null } catch { }

try {
    if ($Remove) {
        Write-Section 'Removing certificates'
        foreach ($t in $Remove) { Remove-CertByThumbprint -Thumbprint $t -QuarantineDir (Join-Path $OutDir 'quarantine\certs') }
        return
    }

    Write-Section ('Certificate audit on {0}' -f $env:COMPUTERNAME)
    $certs = @(Get-AllCerts)
    Write-Info ('{0} certificates across all stores' -f $certs.Count)

    $msRoots = $null
    if (-not $Offline) {
        Write-Info "Downloading Microsoft's trusted root list (certutil -generateSSTFromWU)..."
        $msRoots = Get-MicrosoftTrustedRoots
        if ($msRoots) { Write-Good ('{0} roots in the Microsoft program' -f $msRoots.Count) }
        else { Write-Warn 'Could not get the Microsoft root list (no internet?). Root checks rely on the baseline only.' }
    }
    $enterprise = Get-RegistryThumbprints 'HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates'
    $gpo = Get-RegistryThumbprints 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates'
    $localReg = Get-RegistryThumbprints 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates'
    foreach ($c in $certs) { Set-CertScore -C $c -MsRoots $msRoots -Enterprise $enterprise -Gpo $gpo -LocalReg $localReg }

    $defaultBaseline = Join-Path $baselineDir 'certificates.csv'
    if (-not $Baseline -and -not $SaveBaseline -and (Test-Path -LiteralPath $defaultBaseline)) { $Baseline = $defaultBaseline }
    $removedSince = @()
    if ($Baseline) {
        Write-Info ('Comparing with baseline {0}' -f $Baseline)
        $base = @{}
        foreach ($b in @(Import-Csv -LiteralPath $Baseline)) { $base[('{0}|{1}|{2}' -f $b.Location, $b.Store, $b.Thumbprint)] = $b }
        $seen = @{}
        foreach ($c in $certs) {
            $k = '{0}|{1}|{2}' -f $c.Location, $c.Store, $c.Thumbprint
            $seen[$k] = $true
            if (-not $base.ContainsKey($k)) {
                $c.Baseline = 'NEW'
                if ($c.Store -in $script:TrustStores) { $c.Score += 3 } else { $c.Score += 1 }
                $c.Reasons = (@('added since baseline') + @($c.Reasons | Where-Object { $_ })) -join '; '
            } else { $c.Baseline = 'same' }
        }
        $removedSince = @($base.Keys | Where-Object { -not $seen.ContainsKey($_) } | ForEach-Object { $base[$_] })
    }

    Write-Section ('Certificates to review (score >= {0})' -f $MinScore)
    $hits = @($certs | Where-Object { $_.Score -ge $MinScore } | Sort-Object -Property @{ Expression = 'Score'; Descending = $true }, Store)
    if ($hits.Count -eq 0) { Write-Good 'Nothing to review.' }
    foreach ($h in $hits) {
        $color = 'Yellow'
        if ($h.Score -ge 4) { $color = 'Red' }
        Write-Host ('[{0,2}] {1}\{2}  {3}' -f $h.Score, $h.Location, $h.Store, $h.Subject) -ForegroundColor $color
        Write-Host ('      thumbprint {0}  issuer {1}' -f $h.Thumbprint, $h.Issuer) -ForegroundColor $color
        Write-Host ('      valid {0:yyyy-MM-dd} to {1:yyyy-MM-dd}  source {2}  EKU {3}' -f $h.NotBefore, $h.NotAfter, $h.Source, $h.EKU) -ForegroundColor $color
        Write-Host ('      why: {0}' -f $h.Reasons) -ForegroundColor $color
    }

    $sensitiveRemoved = @($removedSince | Where-Object { $_.Store -eq 'Disallowed' -or $_.Store -in $script:TrustStores })
    if ($sensitiveRemoved.Count) {
        Write-Section 'Removed since baseline (trust stores / Disallowed)'
        foreach ($r in $sensitiveRemoved) {
            $msg = ('{0}\{1}  {2}  {3}' -f $r.Location, $r.Store, $r.Subject, $r.Thumbprint)
            if ($r.Store -eq 'Disallowed') { Write-Bad ($msg + '  <-- a distrusted cert is trusted again') } else { Write-Warn $msg }
        }
    }

    $ntauth = @(Get-NTAuthFindings)
    if ($ntauth.Count) {
        Write-Section 'AD NTAuth store (CAs allowed to issue logon certificates)'
        foreach ($n in $ntauth) {
            if ($n.IsEnterpriseCA) { Write-Good ('{0}  {1}' -f $n.Subject, $n.Thumbprint) }
            else { Write-Bad ('{0}  {1}  <-- not one of your enterprise CAs' -f $n.Subject, $n.Thumbprint) }
        }
    }

    $certs | Select-Object Score, Baseline, Reasons, Location, Store, Subject, Issuer, Thumbprint, NotBefore, NotAfter, HasPrivateKey, SelfSigned, EKU, Source |
        Sort-Object -Property @{ Expression = 'Score'; Descending = $true } |
        Export-Csv (Join-Path $reportDir 'certificates.csv') -NoTypeInformation -Encoding UTF8

    if ($SaveBaseline) {
        $certs | Select-Object Location, Store, Thumbprint, Subject, Issuer, NotBefore, NotAfter |
            Export-Csv -LiteralPath $defaultBaseline -NoTypeInformation -Encoding UTF8
        Copy-Item -LiteralPath $defaultBaseline -Destination (Join-Path $baselineDir ('certificates-{0}.csv' -f $stamp))
        Write-Good ('Baseline saved: {0}' -f $defaultBaseline)
    }

    Write-Section 'Done'
    Write-Info ('Full list: {0}' -f (Join-Path $reportDir 'certificates.csv'))
    Write-Info 'Remove a bad cert (exports a copy first): .\certificates-baseline-compare.ps1 -Remove <thumbprint>'
} finally {
    try { Stop-Transcript | Out-Null } catch { }
}
