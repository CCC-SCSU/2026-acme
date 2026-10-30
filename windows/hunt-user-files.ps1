<#
.SYNOPSIS
    Points out suspicious files in user profiles, temp folders and other common drop locations.

.DESCRIPTION
    Walks C:\Users (every profile + Public), Windows\Temp, C:\Temp, ProgramData, PerfLogs, the Recycle Bin,
    Windows\Tasks|Tracing|debug, spool\drivers\color, web roots, and loose files at C:\ root.
    Each file is scored:
      - executables / scripts / shortcuts / archives / credential files by extension
      - known offensive tool names (mimikatz, rubeus, sharphound, nc, chisel, ...)
      - an MZ header behind a non-executable extension, double extensions (invoice.pdf.exe)
      - Startup folders, spool\drivers\color and other classic drop spots
      - hidden files, alternate data streams, recent changes
      - script / web-shell content keywords (IEX, DownloadString, eval(, shell_exec, Process.Start ...)
      - Authenticode: Microsoft-signed lowers the score, a broken signature raises it
    Also lists non-standard folders at C:\ root and a per-profile summary.
    -SaveBaseline / -Baseline: report files that are new or changed since the last snapshot.

.EXAMPLE
    .\hunt-user-files.ps1
.EXAMPLE
    .\hunt-user-files.ps1 -Days 2 -IncludeAllRecent      # everything touched in the last 2 days
.EXAMPLE
    .\hunt-user-files.ps1 -Paths D:\Shares -Hash
#>
[CmdletBinding()]
param(
    [string[]]$Paths,
    [int]$Days = 14,
    [int]$MinScore = 3,
    [switch]$IncludeAllRecent,
    [switch]$Hash,
    [int]$MaxDepth = 12,
    [int]$Top = 75,
    [string]$OutDir = 'C:\Backup',
    [string]$Baseline,
    [switch]$SaveBaseline
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

$script:ExeExt     = @('.exe', '.dll', '.sys', '.scr', '.com', '.pif', '.cpl', '.ocx', '.msi', '.msp', '.jar')
$script:ScriptExt  = @('.ps1', '.psm1', '.psd1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.py', '.pl', '.sh')
$script:WebExt     = @('.aspx', '.asp', '.ashx', '.asmx', '.php', '.jsp', '.jspx', '.cfm')
$script:LinkExt    = @('.lnk', '.url', '.scf', '.library-ms', '.searchconnector-ms')
$script:ArchiveExt = @('.zip', '.7z', '.rar', '.tar', '.gz', '.cab', '.iso', '.img', '.vhd', '.vhdx')
$script:SecretExt  = @('.kdbx', '.pfx', '.p12', '.pem', '.key', '.ppk', '.rdp', '.ovpn')
# Extensions red team uses to disguise an executable; only these get the (slower) MZ-header check.
$script:DisguiseExt = @('', '.txt', '.log', '.dat', '.tmp', '.bin', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.pdf',
    '.doc', '.docx', '.xls', '.xlsx', '.csv', '.ini', '.cfg', '.conf', '.json', '.xml', '.css', '.htm', '.html', '.bak', '.old',
    '.db', '.mp3', '.mp4', '.wav')
$script:ToolNames  = 'mimikatz|mimilib|rubeus|sharphound|bloodhound|kerbrute|psexec|paexec|procdump|lazagne|winpeas|linpeas|seatbelt|powerview|powerup|sharpup|invoke-|nishang|chisel|ligolo|plink|ncat|netcat|^nc(64)?\.exe$|socat|beacon|cobalt|sliver|meterpreter|payload|revshell|reverse|backdoor|webshell|cmdasp|juicypotato|printspoofer|godpotato|sweetpotato|impacket|secretsdump|crackmapexec|nxc|responder|inveigh'
$script:ContentRegex = 'FromBase64String|\bIEX\b|Invoke-Expression|DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|Start-BitsTransfer|-enc(odedcommand)?\s|System\.Diagnostics\.Process|ProcessStartInfo|WScript\.Shell|Shell\.Application|eval\s*\(|base64_decode|shell_exec|passthru|proc_open|popen\(|system\s*\(|exec\s*\(|Request\.(Form|QueryString|Item)|Net\.Sockets\.TCPClient|nc(\.exe)?\s+-e|sekurlsa|Add-MpPreference|Set-MpPreference|DisableRealtimeMonitoring|net\s+user\s+\S+\s+\S+\s+/add|net\s+localgroup\s+administrators|vssadmin\s+delete|wevtutil\s+cl'
$script:DefaultRootDirs = @('$recycle.bin', '$winreagent', '$sysreset', 'boot', 'config.msi', 'documents and settings', 'inetpub', 'perflogs',
    'program files', 'program files (x86)', 'programdata', 'recovery', 'system volume information', 'users', 'windows', 'windows.old',
    'onedrivetemp', 'backup', 'tools', 'caps', 'ccdc')
$script:SkipDirRegex = '\\AppData\\Local\\(Microsoft\\Edge|Google\\Chrome|Mozilla\\Firefox|Microsoft\\Windows\\(INetCache|WebCache|Explorer|Notifications))|\\ProgramData\\Microsoft\\Windows Defender\\(Definition Updates|Platform|Scans)|\\WinSxS\\'

function Get-DefaultPaths {
    $p = @('C:\Users', (Join-Path $env:windir 'Temp'), 'C:\Temp', 'C:\tmp', 'C:\ProgramData', 'C:\PerfLogs', 'C:\$Recycle.Bin',
           (Join-Path $env:windir 'Tasks'), (Join-Path $env:windir 'Tracing'), (Join-Path $env:windir 'debug'),
           (Join-Path $env:windir 'System32\spool\drivers\color'), 'C:\inetpub', 'C:\xampp\htdocs', 'C:\wamp64\www')
    @($p | Where-Object { Test-Path -LiteralPath $_ })
}

function Get-FilesSafe([string]$Root, [int]$Depth) {
    # Manual walk: skips junctions (no loops through "Application Data"), survives access-denied folders.
    $stack = New-Object System.Collections.Stack
    $stack.Push([pscustomobject]@{ Path = $Root; Level = 0 })
    while ($stack.Count -gt 0) {
        $item = $stack.Pop()
        if ($item.Path -match $script:SkipDirRegex) { continue }
        try { $entries = (New-Object IO.DirectoryInfo($item.Path)).GetFileSystemInfos() } catch { continue }
        foreach ($e in $entries) {
            if ($e -is [IO.DirectoryInfo]) {
                if (($e.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                if ($item.Level -lt $Depth) { $stack.Push([pscustomobject]@{ Path = $e.FullName; Level = $item.Level + 1 }) }
            } else { $e }
        }
    }
}

function Test-MZ([string]$Path) {
    try {
        $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try { $b = New-Object byte[] 2; if ($fs.Read($b, 0, 2) -ne 2) { return $false }; return ($b[0] -eq 0x4D -and $b[1] -eq 0x5A) }
        finally { $fs.Dispose() }
    } catch { return $false }
}

function Get-FileScore([IO.FileInfo]$F, [datetime]$Since) {
    $score = 0; $why = New-Object System.Collections.Generic.List[string]
    $ext = $F.Extension.ToLowerInvariant()
    $name = $F.Name.ToLowerInvariant()
    $path = $F.FullName.ToLowerInvariant()
    $isExe = $script:ExeExt -contains $ext
    $isScript = $script:ScriptExt -contains $ext
    $isWeb = $script:WebExt -contains $ext
    if ($isExe) { $score += 2; $why.Add('executable') }
    elseif ($isScript) { $score += 2; $why.Add('script') }
    elseif ($isWeb) { $score += 1; $why.Add('server-side web page') }
    elseif ($script:LinkExt -contains $ext) { $score += 1; $why.Add('shortcut/link file') }
    elseif ($script:ArchiveExt -contains $ext) { $score += 1; $why.Add('archive/disk image') }
    if ($script:SecretExt -contains $ext -or $name -match 'pass|pwd|cred|secret|unattend|sysprep|\.kdbx$') { $score += 2; $why.Add('credential-looking file') }
    if ($name -match $script:ToolNames) { $score += 4; $why.Add('offensive tool name') }
    if ($name -match '\.(pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|gif|zip)\.(exe|scr|com|bat|cmd|ps1|vbs|js|hta|lnk)$') { $score += 3; $why.Add('double extension') }
    if (-not $isExe -and $script:DisguiseExt -contains $ext -and $F.Length -gt 256 -and $F.Length -lt 100MB -and (Test-MZ $F.FullName)) { $score += 4; $why.Add(('executable disguised as {0}' -f $ext)) }
    if ($path -match '\\start menu\\programs\\startup\\') { $score += 3; $why.Add('Startup folder') }
    if ($path -match '\\spool\\drivers\\color\\' -and ($isExe -or $isScript)) { $score += 3; $why.Add('classic drop folder (spool\color)') }
    if ($path -match '\\windows\\(tasks|tracing|debug)\\' -and ($isExe -or $isScript)) { $score += 2; $why.Add('executable in a Windows writable folder') }
    if ($path -match '\\users\\public\\|\\windows\\temp\\|\\\$recycle\.bin\\|\\perflogs\\') { $score += 1; $why.Add('shared/temp drop location') }
    if ($path -match '^c:\\users\\[^\\]+\\[^\\]+$' -and ($isExe -or $isScript)) { $score += 1; $why.Add('loose in profile root') }
    if (($F.Attributes -band [IO.FileAttributes]::Hidden) -and $name -notin 'desktop.ini', 'thumbs.db' -and $name -notlike 'ntuser*') { $score += 1; $why.Add('hidden') }
    if ($F.LastWriteTime -gt $Since -or $F.CreationTime -gt $Since) { $score += 1; $why.Add('recent') }
    if (($isScript -or $isWeb) -and $F.Length -lt 2MB) {
        try {
            $text = [IO.File]::ReadAllText($F.FullName)
            $kw = @([regex]::Matches($text, $script:ContentRegex, 'IgnoreCase') | ForEach-Object { $_.Value } | Select-Object -Unique)
            if ($kw.Count) { $score += [Math]::Min(4, $kw.Count + 1); $why.Add(('content: ' + (($kw | Select-Object -First 5) -join ', '))) }
        } catch { }
    }
    [pscustomobject]@{ Score = $score; Reasons = $why }
}

function Add-DeepChecks($Row, [IO.FileInfo]$F) {
    # Slower checks, only for files that already look interesting.
    try {
        $streams = @(Get-Item -LiteralPath $F.FullName -Stream * -ErrorAction Stop |
            Where-Object { $_.Stream -notin ':$DATA', 'Zone.Identifier', 'SmartScreen', 'Afp_AfpInfo', 'encryptable' })
        if ($streams.Count) { $Row.Score += 3; $Row.Reasons += ('; alternate data stream: ' + (($streams | ForEach-Object { $_.Stream }) -join ',')) }
    } catch { }
    $ext = $F.Extension.ToLowerInvariant()
    if ($script:ExeExt -contains $ext -or $script:ScriptExt -contains $ext) {
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $F.FullName -ErrorAction Stop
            $Row.Signature = [string]$sig.Status
            if ($sig.SignerCertificate) { $Row.Signer = ($sig.SignerCertificate.Subject -replace '^CN=([^,]+).*$', '$1') }
            if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'O=Microsoft Corporation') { $Row.Score -= 3; $Row.Reasons += '; Microsoft-signed' }
            elseif ($sig.Status -eq 'Valid') { $Row.Score -= 1; $Row.Reasons += '; signed' }
            elseif ($sig.Status -eq 'HashMismatch') { $Row.Score += 4; $Row.Reasons += '; SIGNATURE BROKEN (file modified after signing)' }
            elseif ($sig.Status -eq 'NotSigned' -and $script:ExeExt -contains $ext) { $Row.Score += 1; $Row.Reasons += '; unsigned' }
        } catch { }
    }
    try { $Row.Owner = (Get-Acl -LiteralPath $F.FullName).Owner } catch { }
    if ($Hash) { try { $Row.SHA256 = (Get-FileHash -LiteralPath $F.FullName -Algorithm SHA256).Hash } catch { } }
}

# ---------------------------------------------------------------- main
if ($MyInvocation.InvocationName -eq '.') { return }
if (-not (Test-IsAdmin)) { Write-Bad 'Run this from an elevated PowerShell (otherwise other users'' folders are skipped).'; exit 1 }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportDir = Join-Path $OutDir ('reports\user-files-{0}' -f $stamp)
$baselineDir = Join-Path $OutDir 'baselines'
New-Item -ItemType Directory -Path $reportDir, $baselineDir -Force | Out-Null
try { Start-Transcript -Path (Join-Path $reportDir 'transcript.txt') -Force | Out-Null } catch { }

try {
    $since = (Get-Date).AddDays(-$Days)
    if (-not $Paths) { $Paths = Get-DefaultPaths }
    Write-Section ('File hunt on {0}' -f $env:COMPUTERNAME)
    Write-Info ('Scanning: {0}' -f ($Paths -join ', '))

    $rows = New-Object System.Collections.Generic.List[object]
    $count = 0
    $files = @()
    foreach ($p in $Paths) { $files += @(Get-FilesSafe -Root $p -Depth $MaxDepth) }
    foreach ($f in @(Get-ChildItem -LiteralPath 'C:\' -File -Force -ErrorAction SilentlyContinue)) {
        if ($f.Name -notin 'pagefile.sys', 'swapfile.sys', 'hiberfil.sys', 'bootmgr', 'BOOTNXT', 'BOOTSECT.BAK', 'DumpStack.log', 'DumpStack.log.tmp') { $files += $f }
    }
    Write-Info ('{0} files found, scoring...' -f $files.Count)

    foreach ($f in $files) {
        $count++
        $s = Get-FileScore -F $f -Since $since
        $recent = ($f.LastWriteTime -gt $since -or $f.CreationTime -gt $since)
        if ($s.Score -lt 1 -and -not ($IncludeAllRecent -and $recent)) { continue }
        $rows.Add([pscustomobject]@{
            Score = $s.Score; Path = $f.FullName; SizeKB = [Math]::Round($f.Length / 1KB, 1)
            Modified = $f.LastWriteTime; Created = $f.CreationTime; Owner = ''; Signature = ''; Signer = ''; SHA256 = ''
            Reasons = ($s.Reasons -join '; '); Baseline = ''; Recent = $recent
        })
    }
    $byPath = @{}
    foreach ($f in $files) { $byPath[$f.FullName] = $f }
    foreach ($r in $rows) { if ($r.Score -ge ($MinScore - 1)) { Add-DeepChecks -Row $r -F $byPath[$r.Path] } }

    $defaultBaseline = Join-Path $baselineDir 'user-files.csv'
    if (-not $Baseline -and -not $SaveBaseline -and (Test-Path -LiteralPath $defaultBaseline)) { $Baseline = $defaultBaseline }
    if ($Baseline) {
        Write-Info ('Comparing with baseline {0}' -f $Baseline)
        $base = @{}
        foreach ($b in @(Import-Csv -LiteralPath $Baseline)) { $base[$b.Path] = $b }
        foreach ($r in $rows) {
            if (-not $base.ContainsKey($r.Path)) { $r.Baseline = 'NEW'; $r.Score += 2; $r.Reasons = 'new since baseline; ' + $r.Reasons }
            elseif ($base[$r.Path].Modified -ne $r.Modified.ToString('s')) { $r.Baseline = 'CHANGED'; $r.Score += 2; $r.Reasons = 'changed since baseline; ' + $r.Reasons }
            else { $r.Baseline = 'same' }
        }
    }

    Write-Section ('Suspicious files (score >= {0}, top {1})' -f $MinScore, $Top)
    $hits = @($rows | Where-Object { $_.Score -ge $MinScore } | Sort-Object -Property @{ Expression = 'Score'; Descending = $true }, @{ Expression = 'Modified'; Descending = $true })
    if ($hits.Count -eq 0) { Write-Good 'Nothing above the threshold.' }
    foreach ($h in ($hits | Select-Object -First $Top)) {
        $color = 'Yellow'
        if ($h.Score -ge 7) { $color = 'Red' }
        $tag = ''
        if ($h.Baseline -in 'NEW', 'CHANGED') { $tag = ('[{0}] ' -f $h.Baseline) }
        Write-Host ('[{0,2}] {1}{2}' -f $h.Score, $tag, $h.Path) -ForegroundColor $color
        Write-Host ('      {0:yyyy-MM-dd HH:mm}  {1} KB  owner {2}  {3}' -f $h.Modified, $h.SizeKB, $h.Owner, $h.Signature) -ForegroundColor $color
        Write-Host ('      why: {0}' -f $h.Reasons) -ForegroundColor $color
    }
    if ($hits.Count -gt $Top) { Write-Info ('{0} more in the CSV.' -f ($hits.Count - $Top)) }

    if ($IncludeAllRecent) {
        Write-Section ('Everything modified in the last {0} days' -f $Days)
        foreach ($r in @($rows | Where-Object { $_.Recent } | Sort-Object Modified -Descending | Select-Object -First 200)) {
            Write-Info ('{0:yyyy-MM-dd HH:mm}  {1,8} KB  {2}' -f $r.Modified, $r.SizeKB, $r.Path)
        }
    }

    Write-Section 'Non-standard folders at C:\'
    $odd = @(Get-ChildItem -LiteralPath 'C:\' -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $script:DefaultRootDirs -notcontains $_.Name.ToLowerInvariant() })
    if ($odd.Count -eq 0) { Write-Good 'None.' }
    foreach ($d in $odd) { Write-Warn ('{0}  (created {1:yyyy-MM-dd HH:mm}) - scan it with -Paths if unknown' -f $d.FullName, $d.CreationTime) }

    Write-Section 'Per-profile summary'
    foreach ($prof in @(Get-ChildItem -LiteralPath 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue)) {
        $prefix = $prof.FullName + '\'
        $mine = @($rows | Where-Object { $_.Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) })
        $flagged = @($mine | Where-Object { $_.Score -ge $MinScore }).Count
        $line = ('{0,-22} {1,5} interesting files, {2,4} flagged' -f $prof.Name, $mine.Count, $flagged)
        if ($flagged -gt 0) { Write-Warn $line } else { Write-Info $line }
    }

    $rows | Sort-Object -Property @{ Expression = 'Score'; Descending = $true } |
        Select-Object Score, Baseline, Path, SizeKB, Modified, Created, Owner, Signature, Signer, SHA256, Reasons |
        Export-Csv (Join-Path $reportDir 'user-files.csv') -NoTypeInformation -Encoding UTF8

    if ($SaveBaseline) {
        $rows | Select-Object Path, @{ n = 'Modified'; e = { $_.Modified.ToString('s') } }, SizeKB |
            Export-Csv -LiteralPath $defaultBaseline -NoTypeInformation -Encoding UTF8
        Copy-Item -LiteralPath $defaultBaseline -Destination (Join-Path $baselineDir ('user-files-{0}.csv' -f $stamp))
        Write-Good ('Baseline saved: {0}' -f $defaultBaseline)
    }

    Write-Section 'Done'
    Write-Info ('{0} files checked, {1} flagged. Full list: {2}' -f $count, $hits.Count, (Join-Path $reportDir 'user-files.csv'))
    Write-Info 'Quarantine, do not delete: move the file into C:\Backup\quarantine and note it for an incident report.'
} finally {
    try { Stop-Transcript | Out-Null } catch { }
}
