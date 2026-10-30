<#
.SYNOPSIS
    Finds firewall rules that are not Windows defaults (or changed since your baseline) and ranks them by risk.

.DESCRIPTION
    Windows keeps its factory rule set in
        HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules
    (it is what "netsh advfirewall reset" restores). This script compares the live rules against it:
      NEW                  rule ID not in the defaults (added by red team, an installer, or you)
      NEW (Windows-style)  not in defaults but named like a Windows role rule (AD DS, DNS, IIS) - lower risk
      MODIFIED             same rule ID, different ports/addresses/program/action
      ENABLED / DISABLED   default rule whose on/off state changed
      GPO                  rule pushed by Group Policy (fix it in the GPO, not locally)
    It also checks the profiles (firewall off, default-allow inbound, logging) and the firewall services.
    Each finding gets a risk score: inbound allow from anywhere, programs in user folders, shells/LOLBins,
    C2-style ports, and rules that BLOCK your scored service ports.

    -SaveBaseline snapshots the current rules; later runs report what changed since then.

.EXAMPLE
    .\firewall-baseline-compare.ps1
.EXAMPLE
    .\firewall-baseline-compare.ps1 -SaveBaseline      # after hardening; later runs diff against it
#>
[CmdletBinding()]
param(
    [string]$OutDir = 'C:\Backup',
    [string]$Baseline,
    [switch]$SaveBaseline,
    [switch]$ShowAll,
    [int]$MinRisk = 0
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

$script:RegActive   = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
$script:RegDefaults = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules'
$script:RegPolicy   = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules'
$script:C2Ports       = @(1234, 1337, 2222, 4444, 4445, 5555, 6666, 6667, 8888, 9001, 9002, 12345, 31337, 50050)
$script:ServicePorts  = @(53, 80, 88, 135, 389, 443, 445, 464, 636, 3268, 3269, 3389, 5985)

function Read-RuleStore([string]$Path) {
    $h = @{}
    if (-not (Test-Path -LiteralPath $Path)) { return $h }
    $key = Get-Item -LiteralPath $Path
    foreach ($n in $key.GetValueNames()) {
        $v = $key.GetValue($n)
        if ($v -is [string]) { $h[$n] = $v }
    }
    $h
}

function ConvertFrom-RuleString([string]$Text) {
    $fields = @{}
    $parts = @($Text -split '\|' | Where-Object { $_ -ne '' })
    $fields['_Version'] = ''
    if ($parts.Count -gt 0) { $fields['_Version'] = $parts[0] }
    foreach ($p in ($parts | Select-Object -Skip 1)) {
        $i = $p.IndexOf('=')
        if ($i -lt 1) { continue }
        $k = $p.Substring(0, $i); $v = $p.Substring($i + 1)
        if ($fields.ContainsKey($k)) { $fields[$k] = @($fields[$k]) + $v } else { $fields[$k] = $v }
    }
    $fields
}

function Get-NormalizedRule([string]$Text, [switch]$IgnoreActive) {
    $parts = @($Text -split '\|' | Where-Object { $_ -ne '' } | Select-Object -Skip 1)
    if ($IgnoreActive) { $parts = @($parts | Where-Object { $_ -notmatch '^Active=' }) }
    (@($parts | Sort-Object) -join '|').ToLowerInvariant()
}

function Get-RuleDiff([string]$Old, [string]$New) {
    $o = @($Old -split '\|' | Where-Object { $_ -and $_ -notmatch '^(v\d|Active=)' })
    $n = @($New -split '\|' | Where-Object { $_ -and $_ -notmatch '^(v\d|Active=)' })
    $removed = @($o | Where-Object { $n -notcontains $_ } | ForEach-Object { '-' + $_ })
    $added = @($n | Where-Object { $o -notcontains $_ } | ForEach-Object { '+' + $_ })
    ($removed + $added) -join ' '
}

function Get-TokenDiff([string]$Old, [string]$New) {
    # Diff two already-normalized rule strings (keeps the Active= token so enable/disable shows).
    $o = @($Old -split '\|' | Where-Object { $_ })
    $n = @($New -split '\|' | Where-Object { $_ })
    $removed = @($o | Where-Object { $n -notcontains $_ } | ForEach-Object { '-' + $_ })
    $added = @($n | Where-Object { $o -notcontains $_ } | ForEach-Object { '+' + $_ })
    ($removed + $added) -join ' '
}

function Get-FieldValues([hashtable]$Fields, [string]$Pattern) {
    $vals = @()
    foreach ($k in $Fields.Keys) { if ($k -match $Pattern) { $vals += @($Fields[$k]) } }
    (@($vals | Where-Object { $_ } | Select-Object -Unique)) -join ','
}

function Test-BuiltinStyle([string]$Id, [string]$RawName) {
    ([string]$RawName).StartsWith('@') -and ($Id -notmatch '^\{?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\}?$')
}

function Get-RuleSummary([string]$Id, [string]$Text, [hashtable]$NameMap) {
    $f = ConvertFrom-RuleString $Text
    $protoNum = [string]$f['Protocol']
    $proto = $protoNum
    switch ($protoNum) { '6' { $proto = 'TCP' } '17' { $proto = 'UDP' } '1' { $proto = 'ICMPv4' } '58' { $proto = 'ICMPv6' } '' { $proto = 'Any' } }
    $display = [string]$f['Name']
    if ($NameMap.ContainsKey($Id) -and $NameMap[$Id]) { $display = $NameMap[$Id] }
    $edge = ''
    if ([string]$f['Edge'] -eq 'TRUE' -or $f['Defer']) { $edge = 'yes' }
    [pscustomobject]@{
        Id = $Id; DisplayName = $display; RawName = [string]$f['Name']
        Direction = [string]$f['Dir']; Action = [string]$f['Action']; Enabled = ([string]$f['Active'] -eq 'TRUE')
        Protocol = $proto
        LocalPort = (Get-FieldValues $f '^LPort'); RemotePort = (Get-FieldValues $f '^RPort')
        RemoteAddress = (Get-FieldValues $f '^RA'); LocalAddress = (Get-FieldValues $f '^LA')
        Program = [string]$f['App']; Service = [string]$f['Svc']; Profile = (Get-FieldValues $f '^Profile$'); Edge = $edge
    }
}

function Get-PortNumbers([string]$Text) {
    @(([string]$Text -split '[,\-]') | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })
}

function Get-RuleRisk($R) {
    $score = 0; $why = @()
    if (-not $R.Enabled) { return [pscustomobject]@{ Score = 0; Reasons = 'rule is disabled' } }
    $allowIn = ($R.Action -eq 'Allow' -and $R.Direction -eq 'In')
    if ($allowIn) { $score += 2; $why += 'allows inbound' }
    if ($allowIn -and -not $R.RemoteAddress) { $score += 1; $why += 'from any address' }
    if ($allowIn -and -not $R.LocalPort -and -not $R.Program -and -not $R.Service -and $R.Protocol -in 'Any', 'TCP', 'UDP') { $score += 2; $why += 'all ports' }
    $prog = ([string]$R.Program).ToLowerInvariant()
    if ($prog -match '\\users\\|\\appdata\\|\\temp\\|\\programdata\\|\\perflogs\\|\\public\\|\\windows\\tasks\\|recycle') { $score += 3; $why += 'program in a user-writable folder' }
    if ($prog -match '\\(powershell|pwsh|cmd|rundll32|regsvr32|mshta|wscript|cscript|certutil|bitsadmin|nc|ncat|netcat|socat|plink)(\.exe)?$') { $score += 3; $why += 'program is a shell/LOLBin' }
    $ports = @(Get-PortNumbers $R.LocalPort) + @(Get-PortNumbers $R.RemotePort)
    if (@($ports | Where-Object { $script:C2Ports -contains $_ }).Count -gt 0) { $score += 2; $why += 'common C2/backdoor port' }
    if ($R.Edge) { $score += 1; $why += 'edge traversal' }
    if ($R.Action -eq 'Block' -and $R.Direction -eq 'In') {
        $lp = @(Get-PortNumbers $R.LocalPort)
        if (-not $R.LocalPort -or @($lp | Where-Object { $script:ServicePorts -contains $_ }).Count -gt 0) { $score += 3; $why += 'BLOCKS inbound service ports (scoring?)' }
    }
    if ($R.Action -eq 'Block' -and $R.Direction -eq 'Out' -and -not $R.RemoteAddress -and -not $R.RemotePort -and -not $R.Program) { $score += 2; $why += 'blocks all outbound' }
    [pscustomobject]@{ Score = $score; Reasons = ($why -join '; ') }
}

function Get-ProfileFindings {
    $out = @()
    try {
        foreach ($p in @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)) {
            $issues = @()
            if ([string]$p.Enabled -ne 'True') { $issues += 'FIREWALL IS OFF' }
            if ([string]$p.DefaultInboundAction -eq 'Allow') { $issues += 'default inbound action is ALLOW' }
            if ([string]$p.LogBlocked -ne 'True') { $issues += 'blocked connections not logged' }
            $out += [pscustomobject]@{ Profile = $p.Name; Enabled = [string]$p.Enabled; Inbound = [string]$p.DefaultInboundAction
                                       Outbound = [string]$p.DefaultOutboundAction; LogBlocked = [string]$p.LogBlocked; Issues = ($issues -join '; ') }
        }
    } catch { Write-Warn ('Could not read firewall profiles: {0}' -f $_.Exception.Message) }
    $out
}

function Get-Findings([hashtable]$Active, [hashtable]$Defaults, [hashtable]$Policy, [hashtable]$NameMap) {
    $findings = @()
    $haveDefaults = ($Defaults.Count -gt 0)
    foreach ($id in $Active.Keys) {
        $text = $Active[$id]
        $s = Get-RuleSummary -Id $id -Text $text -NameMap $NameMap
        $status = $null; $detail = ''; $adjust = 0
        if ($haveDefaults) {
            if (-not $Defaults.ContainsKey($id)) {
                $status = 'NEW'
                if (Test-BuiltinStyle $id $s.RawName) { $status = 'NEW (Windows-style)'; $adjust = -2 }
            } elseif ((Get-NormalizedRule $text -IgnoreActive) -ne (Get-NormalizedRule $Defaults[$id] -IgnoreActive)) {
                $status = 'MODIFIED'; $detail = Get-RuleDiff $Defaults[$id] $text
            } else {
                $dActive = [string](ConvertFrom-RuleString $Defaults[$id])['Active']
                $aActive = [string](ConvertFrom-RuleString $text)['Active']
                if ($dActive -ne $aActive) {
                    if ($aActive -eq 'TRUE') { $status = 'ENABLED (off by default)'; $adjust = -1 } else { $status = 'DISABLED (on by default)' }
                } elseif ($ShowAll) { $status = 'default' }
            }
        } else {
            if (Test-BuiltinStyle $id $s.RawName) { if ($ShowAll) { $status = 'built-in?' } } else { $status = 'NEW?' }
        }
        if (-not $status) { continue }
        $risk = Get-RuleRisk $s
        $score = [Math]::Max(0, $risk.Score + $adjust)
        if ($status -like 'DISABLED*' -or $status -eq 'default' -or $status -eq 'built-in?') { $score = 0 }
        $findings += [pscustomobject]@{ Status = $status; Risk = $score; Store = 'Local'; Id = $id; DisplayName = $s.DisplayName
            Direction = $s.Direction; Action = $s.Action; Enabled = $s.Enabled; Protocol = $s.Protocol; LocalPort = $s.LocalPort
            RemotePort = $s.RemotePort; RemoteAddress = $s.RemoteAddress; Program = $s.Program; Service = $s.Service
            Profile = $s.Profile; Reasons = $risk.Reasons; Diff = $detail }
    }
    foreach ($id in $Policy.Keys) {
        $s = Get-RuleSummary -Id $id -Text $Policy[$id] -NameMap $NameMap
        $risk = Get-RuleRisk $s
        $findings += [pscustomobject]@{ Status = 'GPO'; Risk = ($risk.Score + 1); Store = 'GroupPolicy'; Id = $id; DisplayName = $s.DisplayName
            Direction = $s.Direction; Action = $s.Action; Enabled = $s.Enabled; Protocol = $s.Protocol; LocalPort = $s.LocalPort
            RemotePort = $s.RemotePort; RemoteAddress = $s.RemoteAddress; Program = $s.Program; Service = $s.Service
            Profile = $s.Profile; Reasons = ('pushed by Group Policy; ' + $risk.Reasons); Diff = '' }
    }
    $findings
}

function Write-Finding($F) {
    $color = 'Gray'
    if ($F.Risk -ge 5) { $color = 'Red' } elseif ($F.Risk -ge 3) { $color = 'Yellow' } elseif ($F.Status -like 'NEW*' -or $F.Status -eq 'GPO') { $color = 'White' }
    Write-Host ('[{0,2}] {1,-24} {2}  ({3})' -f $F.Risk, $F.Status, $F.DisplayName, $F.Id) -ForegroundColor $color
    $parts = @(('{0}/{1}' -f $F.Direction, $F.Action), $F.Protocol)
    if ($F.LocalPort) { $parts += ('lport ' + $F.LocalPort) }
    if ($F.RemotePort) { $parts += ('rport ' + $F.RemotePort) }
    if ($F.RemoteAddress) { $parts += ('from ' + $F.RemoteAddress) } else { $parts += 'from any' }
    if ($F.Program) { $parts += ('app ' + $F.Program) }
    if ($F.Service) { $parts += ('svc ' + $F.Service) }
    Write-Host ('      ' + ($parts -join ' | ')) -ForegroundColor $color
    if ($F.Reasons) { Write-Host ('      why: ' + $F.Reasons) -ForegroundColor $color }
    if ($F.Diff) { Write-Host ('      diff vs default: ' + $F.Diff) -ForegroundColor $color }
}

# ---------------------------------------------------------------- main
if ($MyInvocation.InvocationName -eq '.') { return }
if (-not (Test-IsAdmin)) { Write-Bad 'Run this from an elevated PowerShell.'; exit 1 }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportDir = Join-Path $OutDir ('reports\firewall-{0}' -f $stamp)
$baselineDir = Join-Path $OutDir 'baselines'
New-Item -ItemType Directory -Path $reportDir, $baselineDir -Force | Out-Null
try { Start-Transcript -Path (Join-Path $reportDir 'transcript.txt') -Force | Out-Null } catch { }

try {
    Write-Section ('Firewall audit on {0}' -f $env:COMPUTERNAME)
    foreach ($svcName in 'MpsSvc', 'BFE') {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if (-not $svc) { Write-Bad ('{0} service missing' -f $svcName) }
        elseif ($svc.Status -ne 'Running') { Write-Bad ('{0} is {1} - firewall is not enforcing. Start-Service {0}' -f $svcName, $svc.Status) }
        else { Write-Good ('{0} running' -f $svcName) }
    }

    Write-Section 'Profiles'
    $profiles = @(Get-ProfileFindings)
    foreach ($p in $profiles) {
        $line = ('{0,-8} enabled={1} inbound={2} outbound={3} logBlocked={4}' -f $p.Profile, $p.Enabled, $p.Inbound, $p.Outbound, $p.LogBlocked)
        if ($p.Issues -match 'OFF|ALLOW') { Write-Bad ($line + '  <-- ' + $p.Issues) }
        elseif ($p.Issues) { Write-Warn ($line + '  <-- ' + $p.Issues) }
        else { Write-Good $line }
    }

    $active = Read-RuleStore $script:RegActive
    $defaults = Read-RuleStore $script:RegDefaults
    $policy = Read-RuleStore $script:RegPolicy
    $nameMap = @{}
    try { foreach ($r in @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)) { $nameMap[$r.Name] = $r.DisplayName } } catch { }
    Write-Info ('{0} local rules, {1} Windows default rules, {2} Group Policy rules' -f $active.Count, $defaults.Count, $policy.Count)
    if ($defaults.Count -eq 0) { Write-Warn 'Windows defaults key not found - falling back to name-based guessing (NEW? = not Windows-style).' }

    $findings = @(Get-Findings -Active $active -Defaults $defaults -Policy $policy -NameMap $nameMap)
    $shown = @($findings | Where-Object { $_.Risk -ge $MinRisk } | Sort-Object -Property @{ Expression = 'Risk'; Descending = $true }, Status, DisplayName)

    Write-Section 'Rules that differ from Windows defaults (highest risk first)'
    if ($shown.Count -eq 0) { Write-Good 'Nothing differs from the defaults.' }
    foreach ($f in $shown) { Write-Finding $f }

    $deleted = @($defaults.Keys | Where-Object { -not $active.ContainsKey($_) })
    if ($deleted.Count) {
        Write-Info ('{0} default rules are missing from the live policy (usually harmless).' -f $deleted.Count)
        if ($ShowAll) { foreach ($d in $deleted) { Write-Info ('  deleted default: {0}' -f $d) } }
    }

    $findings | Export-Csv (Join-Path $reportDir 'firewall-findings.csv') -NoTypeInformation -Encoding UTF8
    $profiles | Export-Csv (Join-Path $reportDir 'firewall-profiles.csv') -NoTypeInformation -Encoding UTF8

    # baseline: every live rule (local + GPO), normalized
    $snapRules = @()
    foreach ($id in $active.Keys) { $snapRules += [pscustomobject]@{ Id = $id; Store = 'Local'; Rule = (Get-NormalizedRule $active[$id]) } }
    foreach ($id in $policy.Keys) { $snapRules += [pscustomobject]@{ Id = $id; Store = 'GroupPolicy'; Rule = (Get-NormalizedRule $policy[$id]) } }
    $defaultBaseline = Join-Path $baselineDir 'firewall.csv'
    if (-not $Baseline -and -not $SaveBaseline -and (Test-Path -LiteralPath $defaultBaseline)) { $Baseline = $defaultBaseline }
    if ($Baseline) {
        Write-Section ('Changes since baseline {0}' -f $Baseline)
        $old = @{}
        foreach ($row in @(Import-Csv -LiteralPath $Baseline)) { $old[('{0}|{1}' -f $row.Store, $row.Id)] = $row.Rule }
        $now = @{}
        foreach ($row in $snapRules) { $now[('{0}|{1}' -f $row.Store, $row.Id)] = $row.Rule }
        $changes = 0
        foreach ($k in $now.Keys) {
            $parts = $k -split '\|', 2
            $id = $parts[1]
            $label = $id
            if ($nameMap.ContainsKey($id)) { $label = ('{0} ({1})' -f $nameMap[$id], $id) }
            if (-not $old.ContainsKey($k)) { Write-Bad ('ADDED    [{0}] {1}' -f $parts[0], $label); $changes++ }
            elseif ($old[$k] -ne $now[$k]) { Write-Bad ('CHANGED  [{0}] {1}: {2}' -f $parts[0], $label, (Get-TokenDiff $old[$k] $now[$k])); $changes++ }
        }
        foreach ($k in $old.Keys) { if (-not $now.ContainsKey($k)) { Write-Warn ('REMOVED  {0}' -f $k); $changes++ } }
        if ($changes -eq 0) { Write-Good 'No changes since baseline.' }
    }
    if ($SaveBaseline) {
        $snapRules | Export-Csv -LiteralPath $defaultBaseline -NoTypeInformation -Encoding UTF8
        Copy-Item -LiteralPath $defaultBaseline -Destination (Join-Path $baselineDir ('firewall-{0}.csv' -f $stamp))
        Write-Good ('Baseline saved: {0}' -f $defaultBaseline)
    }

    Write-Section 'Next steps'
    Write-Info 'Disable a bad local rule:   Disable-NetFirewallRule -Name ''<Id>''   (export first: netsh advfirewall export C:\Backup\fw.wfw)'
    Write-Info 'GPO rules come back on refresh - remove them from the GPO (gpmc.msc).'
    Write-Info ('Reports: {0}' -f $reportDir)
} finally {
    try { Stop-Transcript | Out-Null } catch { }
}
