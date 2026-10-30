<#
.SYNOPSIS
    Runs Sysinternals autorunsc, scores every autostart entry for suspicion, and diffs against a baseline.

.DESCRIPTION
    Improvements over a plain autorunsc dump:
      - Verifies autorunsc itself is Microsoft-signed before trusting its output.
      - Keeps Microsoft entries visible (red team hides behind signed powershell/rundll32/mshta) and
        scores the COMMAND LINE: user-writable paths, LOLBins, encoded/download keywords, URLs/IPs,
        scripts, system-process names outside System32, WMI and other sensitive autostart categories.
      - Baseline diff: NEW and CHANGED (launch string or file hash) entries since -SaveBaseline,
        or since a baseline taken on a clean VM of the same OS (-Baseline <file>).
      - Hidden scheduled task check: tasks whose security descriptor was deleted from the registry
        (Tarrask-style) so Task Scheduler and autoruns never show them.
      - Optional VirusTotal hash lookups (-VirusTotal, needs internet).

.EXAMPLE
    .\autoruns-baseline-compare.ps1
.EXAMPLE
    .\autoruns-baseline-compare.ps1 -SaveBaseline           # after cleanup; later runs show only changes + high scores
.EXAMPLE
    .\autoruns-baseline-compare.ps1 -Baseline E:\clean-vm-autoruns.csv -MinScore 5
#>
[CmdletBinding()]
param(
    [string]$AutorunsPath,
    [string]$OutDir = 'C:\Backup',
    [string]$Baseline,
    [switch]$SaveBaseline,
    [switch]$VirusTotal,
    [int]$MinScore = 3,
    [int]$RecentDays = 30,
    [string]$InputCsv
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

$script:Lolbins = 'powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msbuild|installutil|regasm|regsvcs|wmic|forfiles|curl|nc|ncat|netcat|socat|plink|msiexec'
$script:SystemNames = 'svchost|lsass|csrss|winlogon|services|smss|spoolsv|taskhostw|dllhost|conhost|rundll32|wininit|lsm|explorer'

function Find-Autorunsc {
    if ($AutorunsPath) {
        if (Test-Path -LiteralPath $AutorunsPath) { return (Resolve-Path -LiteralPath $AutorunsPath).ProviderPath }
        Write-Bad ('-AutorunsPath {0} not found' -f $AutorunsPath); return $null
    }
    $names = @('autorunsc64.exe', 'autorunsc.exe')
    if (-not [Environment]::Is64BitOperatingSystem) { $names = @('autorunsc.exe') }
    $dirs = @($PSScriptRoot, (Get-Location).ProviderPath, 'C:\Tools', 'C:\Tools\Sysinternals', 'C:\Tools\SysinternalsSuite', 'C:\Sysinternals', 'C:\SysinternalsSuite')
    foreach ($d in $dirs) {
        if (-not $d) { continue }
        foreach ($n in $names) { $p = Join-Path $d $n; if (Test-Path -LiteralPath $p) { return $p } }
    }
    foreach ($n in $names) { $c = Get-Command $n -ErrorAction SilentlyContinue; if ($c) { return $c.Source } }
    $hit = Get-ChildItem -Path 'C:\Tools' -Recurse -Filter $names[0] -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($hit) { return $hit.FullName }
    $null
}

function Invoke-Autorunsc([string]$Exe, [string]$OutFile) {
    $a = @('-accepteula', '-a', '*', '-c', '-h', '-s', '-t')
    if ($VirusTotal) { $a += @('-v', '-vt') }
    & $Exe @a -o $OutFile '*' 2>&1 | Out-Null
    if ((Test-Path -LiteralPath $OutFile) -and (Get-Item -LiteralPath $OutFile).Length -gt 100) { return }
    Write-Warn 'autorunsc did not write output with -o/-t; retrying with basic options.'
    $cmd = '"{0}" -accepteula -a * -c -h -s * > "{1}"' -f $Exe, $OutFile
    & cmd.exe /c $cmd 2>&1 | Out-Null
}

function Read-ToolCsv([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 4) { return @() }
    $enc = [Text.Encoding]::UTF8
    if ($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { $enc = [Text.Encoding]::Unicode }
    elseif ($bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) { $enc = [Text.Encoding]::BigEndianUnicode }
    elseif ($bytes[1] -eq 0 -and $bytes[3] -eq 0) { $enc = [Text.Encoding]::Unicode }
    $text = $enc.GetString($bytes).TrimStart([char]0xFEFF)
    $lines = @($text -split "`r?`n")
    $start = 0
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^"?(Time|Entry Location)"?,') { $start = $i; break } }
    @($lines[$start..($lines.Count - 1)] | Where-Object { $_.Trim() }) | ConvertFrom-Csv
}

function Get-Field($Row, [string]$Name) {
    $p = $Row.PSObject.Properties[$Name]
    if ($p -and $null -ne $p.Value) { return [string]$p.Value }
    ''
}

function ConvertTo-NormalizedText([string]$Text) {
    $t = ([string]$Text).ToLowerInvariant()
    $t = $t -replace 'c:\\users\\[^\\]+\\', '%userprofile%\'
    ($t -replace '\s+', ' ').Trim()
}

function ConvertTo-AutorunEntry($Row) {
    $e = [pscustomobject]@{
        Time = (Get-Field $Row 'Time'); Location = (Get-Field $Row 'Entry Location'); Entry = (Get-Field $Row 'Entry')
        Enabled = (Get-Field $Row 'Enabled'); Category = (Get-Field $Row 'Category'); Profile = (Get-Field $Row 'Profile')
        Description = (Get-Field $Row 'Description'); Signer = (Get-Field $Row 'Signer'); Company = (Get-Field $Row 'Company')
        ImagePath = (Get-Field $Row 'Image Path'); LaunchString = (Get-Field $Row 'Launch String'); SHA256 = (Get-Field $Row 'SHA-256')
        VT = (Get-Field $Row 'VT detection'); Key = ''; Score = 0; Reasons = ''; Baseline = ''
    }
    $prof = $e.Profile
    if ($prof -and $prof -ne 'System-wide') { $prof = ($prof -split '\\')[-1] }
    $e.Key = (@($e.Category, $e.Location, $e.Entry, $prof) | ForEach-Object { ConvertTo-NormalizedText $_ }) -join '|'
    $e
}

function Add-Reason($Entry, [int]$Points, [string]$Why) {
    $Entry.Score += $Points
    if ($Entry.Reasons) { $Entry.Reasons += '; ' + $Why } else { $Entry.Reasons = $Why }
}

function Set-AutorunScore($E) {
    $launch = $E.LaunchString.ToLowerInvariant()
    $img = $E.ImagePath.ToLowerInvariant()
    $both = $launch + ' ' + $img
    $verified = $E.Signer -match '^\(Verified\)'
    $msVerified = $verified -and ($E.Signer -match 'Microsoft')
    if (-not $verified) {
        if (-not $img -or $img -match '^file not found') { Add-Reason $E 1 'image file missing' }
        else { Add-Reason $E 3 'not signed / signature not verified' }
    }
    if ($both -match '\\users\\|\\appdata\\|\\temp\\|\\programdata\\|\\perflogs\\|\\windows\\tasks\\|\$recycle\.bin|\\windows\\debug\\|\\spool\\drivers\\color\\') {
        Add-Reason $E 3 'runs from a user-writable or unusual folder'
    }
    if ($launch -match ('(^|[\\\s"''/])(' + $script:Lolbins + ')(\.exe)?([\s"'']|$)')) { Add-Reason $E 2 ('launches ' + $Matches[2]) }
    if ($launch -match '-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{20,}|frombase64string|\biex\b|invoke-expression|downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|-w(indowstyle)?\s+h(idden)?\b|-nop\b|-ex(ecutionpolicy)?\s+bypass|start-bitstransfer') {
        Add-Reason $E 3 'download / obfuscation keywords'
    }
    if ($launch -match 'https?://') { Add-Reason $E 2 'URL in command line' }
    if ($launch -match '(https?://|\\\\|@|\s)\d{1,3}(\.\d{1,3}){3}(:\d+)?([\s/''"]|$)') { Add-Reason $E 2 'IP address in command line' }
    if ($launch -match '\.(ps1|vbs|vbe|js|jse|hta|wsf|bat|cmd|scr)\b' -and $img -notmatch '\.(bat|cmd)$') { Add-Reason $E 1 'runs a script file' }
    $leaf = [IO.Path]::GetFileName(($img -replace '^file not found:\s*', ''))
    if ($leaf -match ('^(' + $script:SystemNames + ')\.exe$') -and $img -notmatch '\\windows\\(system32|syswow64)\\' -and -not ($leaf -eq 'explorer.exe' -and $img -match '\\windows\\explorer\.exe$')) {
        Add-Reason $E 4 'system process name outside System32'
    }
    if ($E.Category -match 'WMI') { Add-Reason $E 2 'WMI persistence' }
    if (-not $msVerified -and $E.Category -match 'Hijack|LSA|Winlogon|Known|AppInit|Boot|Print Monitor|Winsock|Network Provider') { Add-Reason $E 2 ('sensitive category: ' + $E.Category) }
    if ($E.Time -match '^\d{8}-\d{6}$') {
        $t = [datetime]::ParseExact($E.Time, 'yyyyMMdd-HHmmss', [Globalization.CultureInfo]::InvariantCulture)
        if ($t -gt (Get-Date).ToUniversalTime().AddDays(-$RecentDays)) { Add-Reason $E 1 ('changed in last {0} days' -f $RecentDays) }
    }
    if ($E.VT -match '^(\d+)\|' -and [int]$Matches[1] -gt 0) { Add-Reason $E 5 ('VirusTotal ' + $E.VT) }
}

function Compare-AutorunBaseline([object[]]$Entries, [string]$BaselinePath) {
    $base = @{}
    foreach ($b in @(Import-Csv -LiteralPath $BaselinePath)) { $base[$b.Key] = $b }
    $seen = @{}
    foreach ($e in $Entries) {
        $seen[$e.Key] = $true
        if (-not $base.ContainsKey($e.Key)) { $e.Baseline = 'NEW'; Add-Reason $e 3 'not in baseline'; continue }
        $b = $base[$e.Key]
        $what = @()
        if ((ConvertTo-NormalizedText $e.LaunchString) -ne $b.Launch) { $what += 'launch string' }
        if ($e.SHA256 -and $b.SHA256 -and $e.SHA256 -ne $b.SHA256) { $what += 'file hash' }
        if ($what.Count) { $e.Baseline = 'CHANGED'; Add-Reason $e 3 ('changed since baseline: ' + ($what -join ', ')) } else { $e.Baseline = 'same' }
    }
    @($base.Keys | Where-Object { -not $seen.ContainsKey($_) } | ForEach-Object { $base[$_] })
}

function Find-HiddenTasks {
    $tree = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'
    try { $keys = @(Get-ChildItem -LiteralPath $tree -Recurse -ErrorAction Stop) }
    catch { Write-Warn ('Cannot read TaskCache ({0}). Run as SYSTEM (psexec -s) to check for hidden tasks.' -f $_.Exception.Message); return }
    $visible = @{}
    try { foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) { $visible[($t.TaskPath + $t.TaskName).ToLowerInvariant()] = $true } } catch { }
    $out = @(); $tasks = 0; $noSd = 0
    foreach ($k in $keys) {
        $id = $k.GetValue('Id')
        if (-not $id) { continue }
        $tasks++
        $path = $k.Name -replace '^.*\\TaskCache\\Tree', ''
        $why = @()
        if ($null -eq $k.GetValue('SD')) { $why += 'security descriptor deleted (hidden task)'; $noSd++ }
        if ($visible.Count -gt 0 -and -not $visible.ContainsKey($path.ToLowerInvariant())) { $why += 'not returned by Get-ScheduledTask' }
        if ($why.Count -eq 0) { continue }
        $action = ''
        $xml = Join-Path $env:windir ('System32\Tasks{0}' -f $path)
        if (Test-Path -LiteralPath $xml) {
            try {
                [xml]$doc = Get-Content -LiteralPath $xml -Raw
                $action = (@($doc.Task.Actions.Exec) | ForEach-Object { '{0} {1}' -f $_.Command, $_.Arguments }) -join '; '
            } catch { }
        }
        $out += [pscustomobject]@{ Task = $path; Id = $id; Why = ($why -join '; '); Action = $action; Severity = $(if ($why[0] -like 'security*') { 'HIGH' } else { 'check' }) }
    }
    if ($tasks -gt 10 -and $noSd -gt ($tasks / 2)) {
        # Most tasks "missing" SD means this account just can't read the value, not that they are all hidden.
        Write-Warn ('SD value unreadable on {0} of {1} tasks - re-run as SYSTEM (psexec -s -i powershell) for the hidden-task check.' -f $noSd, $tasks)
        $out = @($out | Where-Object { $_.Why -like '*Get-ScheduledTask*' })
        foreach ($o in $out) { $o.Severity = 'check' }
    }
    $out
}

# ---------------------------------------------------------------- main
if ($MyInvocation.InvocationName -eq '.') { return }
if (-not (Test-IsAdmin)) { Write-Bad 'Run this from an elevated PowerShell.'; exit 1 }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportDir = Join-Path $OutDir ('reports\autoruns-{0}' -f $stamp)
$baselineDir = Join-Path $OutDir 'baselines'
New-Item -ItemType Directory -Path $reportDir, $baselineDir -Force | Out-Null
try { Start-Transcript -Path (Join-Path $reportDir 'transcript.txt') -Force | Out-Null } catch { }

try {
    Write-Section ('Autoruns audit on {0}' -f $env:COMPUTERNAME)
    $raw = $InputCsv
    if (-not $raw) {
        $exe = Find-Autorunsc
        if (-not $exe) { Write-Bad 'autorunsc not found. Put autorunsc64.exe next to this script or in C:\Tools, or pass -AutorunsPath.'; return }
        $sig = Get-AuthenticodeSignature -LiteralPath $exe
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
            Write-Bad ('{0} is NOT validly Microsoft-signed ({1}). Re-download Sysinternals before trusting it.' -f $exe, $sig.Status)
            return
        }
        Write-Good ('Using {0} (Microsoft-signed)' -f $exe)
        $raw = Join-Path $reportDir 'autoruns-raw.csv'
        Write-Info 'Running autorunsc (1-3 minutes, longer with -VirusTotal)...'
        Invoke-Autorunsc -Exe $exe -OutFile $raw
    }
    if (-not (Test-Path -LiteralPath $raw)) { Write-Bad 'No autorunsc output to analyze.'; return }

    $entries = @(Read-ToolCsv $raw | ForEach-Object { ConvertTo-AutorunEntry $_ } | Where-Object { $_.Entry -or $_.ImagePath })
    Write-Info ('{0} autostart entries' -f $entries.Count)
    foreach ($e in $entries) { Set-AutorunScore $e }

    $defaultBaseline = Join-Path $baselineDir 'autoruns.csv'
    if (-not $Baseline -and -not $SaveBaseline -and (Test-Path -LiteralPath $defaultBaseline)) { $Baseline = $defaultBaseline }
    $removed = @()
    if ($Baseline) {
        Write-Info ('Comparing with baseline {0}' -f $Baseline)
        $removed = @(Compare-AutorunBaseline -Entries $entries -BaselinePath $Baseline)
    }

    Write-Section ('Suspicious entries (score >= {0}, highest first)' -f $MinScore)
    $hits = @($entries | Where-Object { $_.Score -ge $MinScore } | Sort-Object -Property @{ Expression = 'Score'; Descending = $true }, Category, Entry)
    if ($hits.Count -eq 0) { Write-Good 'Nothing scored above the threshold.' }
    foreach ($h in $hits) {
        $color = 'Yellow'
        if ($h.Score -ge 6) { $color = 'Red' }
        $tag = ''
        if ($h.Baseline -in 'NEW', 'CHANGED') { $tag = ('[{0}] ' -f $h.Baseline) }
        Write-Host ('[{0,2}] {1}{2} :: {3}' -f $h.Score, $tag, $h.Category, $h.Entry) -ForegroundColor $color
        Write-Host ('      where : {0}' -f $h.Location) -ForegroundColor $color
        Write-Host ('      runs  : {0}' -f $h.LaunchString) -ForegroundColor $color
        Write-Host ('      signer: {0}   profile: {1}' -f $h.Signer, $h.Profile) -ForegroundColor $color
        Write-Host ('      why   : {0}' -f $h.Reasons) -ForegroundColor $color
    }
    if ($removed.Count) {
        Write-Section 'In baseline but gone now (you removed it, or something was replaced)'
        foreach ($r in $removed) { Write-Info ('{0} :: {1}' -f $r.Category, $r.Entry) }
    }

    Write-Section 'Hidden scheduled tasks'
    $hidden = @(Find-HiddenTasks)
    if ($hidden.Count -eq 0) { Write-Good 'None found.' }
    foreach ($t in $hidden) {
        $line = ('[{0}] {1}  {2}  {3}' -f $t.Severity, $t.Task, $t.Why, $t.Action)
        if ($t.Severity -eq 'HIGH') { Write-Bad $line } else { Write-Warn $line }
    }

    $entries | Sort-Object -Property @{ Expression = 'Score'; Descending = $true } |
        Select-Object Score, Baseline, Reasons, Category, Entry, Location, LaunchString, ImagePath, Signer, Company, Profile, Enabled, Time, SHA256, VT |
        Export-Csv (Join-Path $reportDir 'autoruns-scored.csv') -NoTypeInformation -Encoding UTF8
    if ($hidden.Count) { $hidden | Export-Csv (Join-Path $reportDir 'hidden-tasks.csv') -NoTypeInformation -Encoding UTF8 }

    if ($SaveBaseline) {
        $entries | Select-Object Key, @{ n = 'Launch'; e = { ConvertTo-NormalizedText $_.LaunchString } }, SHA256, Signer, Category, Location, Entry, Profile, ImagePath |
            Export-Csv -LiteralPath $defaultBaseline -NoTypeInformation -Encoding UTF8
        Copy-Item -LiteralPath $defaultBaseline -Destination (Join-Path $baselineDir ('autoruns-{0}.csv' -f $stamp))
        Write-Good ('Baseline saved: {0}' -f $defaultBaseline)
    }

    Write-Section 'Done'
    Write-Info ('{0} entries scored >= {1}. Full scored list: {2}' -f $hits.Count, $MinScore, (Join-Path $reportDir 'autoruns-scored.csv'))
    Write-Info 'Disable an entry in the Autoruns GUI (untick) before deleting it, so you can undo if it was legit.'
} finally {
    try { Stop-Transcript | Out-Null } catch { }
}
