<#
.SYNOPSIS
    Resets every enabled user's password to a new random one and writes the passwords to a CSV for the scoring engine.

.DESCRIPTION
    Always skipped (automatic):
        built-in Administrator (RID 500, even if renamed), Guest (501), krbtgt (502) and RODC krbtgt_* accounts,
        DefaultAccount (503), WDAGUtilityAccount (504), the account running this script, names ending in $
        (trust / machine accounts), and disabled accounts (unless -IncludeDisabled)
    Skip more with any mix of:
        -Exclude       names or wildcards:  -Exclude svc_sql,svc_web,'backup*'
        -ExcludeFile   one name per line (DOMAIN\ or @domain is stripped, # = comment) - e.g. the
                       service-accounts.txt that inventory-domain.ps1 writes
        -ExcludeGroup  every member of a group (nested):  -ExcludeGroup 'Service Accounts'
    Accounts that look like service accounts (have an SPN or a svc-style name) but are NOT excluded are listed
    before you confirm, and any -Exclude pattern that matches nobody is flagged (catches typos).

    Order of operations, so a crash can never leave you with unknown passwords:
      1. Builds and shows the list. -WhatIf stops here (nothing changed, no file written).
      2. You type RESET (or pass -Force).
      3. Every new password is written to a locked-down working file BEFORE anything changes.
      4. Each account: password reset, "must change password at next logon" cleared (the scorer can't do that),
         unlocked if locked. A status line per account is appended to results.csv as it goes.
      5. Each new password is tested with a real login check against the same DC.
      6. Writes the submission CSV (every account whose reset succeeded) and deletes the working file.
    Passwords: letters and digits only (nothing that breaks a CSV or a scoring engine), 16 long by default,
    always upper + lower + digit, no look-alike characters (0 O 1 l I), never containing the account name.

    -Local resets local accounts on a member server / workstation instead of domain accounts.
    Files go to C:\Backup\passwords\<time>\ with only Administrators and SYSTEM allowed to read them.

.EXAMPLE
    .\reset-passwords.ps1 -WhatIf
.EXAMPLE
    .\reset-passwords.ps1 -Exclude svc_sql,svc_iis,'backup*'
.EXAMPLE
    .\reset-passwords.ps1 -ExcludeFile C:\Backup\reports\inventory-20261031-091500\service-accounts.txt
.EXAMPLE
    .\reset-passwords.ps1 -UserColumn user -PasswordColumn pass -DomainPrefix    # match the format the ISE asks for
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string[]]$Exclude,
    [string]$ExcludeFile,
    [string[]]$ExcludeGroup,
    [string]$SearchBase,
    [switch]$IncludeDisabled,
    [switch]$Local,
    [ValidateRange(12, 64)][int]$Length = 16,
    [string]$UserColumn = 'username',
    [string]$PasswordColumn = 'password',
    [string]$Delimiter = ',',
    [switch]$NoHeader,
    [switch]$DomainPrefix,
    [string]$OutDir = 'C:\Backup',
    [switch]$Force
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

# ---------------------------------------------------------------- passwords
$script:Upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
$script:Lower = 'abcdefghijkmnopqrstuvwxyz'
$script:Digit = '23456789'
$script:Rng = [Security.Cryptography.RandomNumberGenerator]::Create()

function Get-RandomIndex([int]$Max) {
    # Unbiased index in [0, Max) from the crypto RNG (rejection sampling).
    $bytes = New-Object byte[] 4
    $limit = 4294967296L - (4294967296L % $Max)
    do {
        $script:Rng.GetBytes($bytes)
        $v = [int64][BitConverter]::ToUInt32($bytes, 0)
    } while ($v -ge $limit)
    [int]($v % $Max)
}

function Get-NameTokens([string]$Sam, [string]$Display) {
    # Windows complexity rejects passwords containing the account name or any 3+ char part of the display name.
    @(@($Sam) + @(([string]$Display) -split '[,.\-_#\s]+') | Where-Object { $_ -and $_.Length -ge 3 })
}

function New-RandomPassword([int]$Len, [string[]]$Avoid) {
    $all = $script:Upper + $script:Lower + $script:Digit
    while ($true) {
        $sb = New-Object Text.StringBuilder
        for ($i = 0; $i -lt $Len; $i++) { [void]$sb.Append($all[(Get-RandomIndex $all.Length)]) }
        $pw = $sb.ToString()
        if (-not ($pw -cmatch '[A-Z]' -and $pw -cmatch '[a-z]' -and $pw -match '[0-9]')) { continue }
        $clash = $false
        foreach ($t in @($Avoid)) { if ($t -and $pw.IndexOf($t, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $clash = $true } }
        if (-not $clash) { return $pw }
    }
}

# ---------------------------------------------------------------- helpers
function Get-BareName([string]$Text) {
    $t = ([string]$Text).Trim()
    if ($t -match '\\') { $t = ($t -split '\\')[-1] }
    if ($t -match '^([^@]+)@') { $t = $Matches[1] }
    $t
}

function Protect-Path([string]$Path) {
    & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
}

function Write-Lines([string]$Path, [string[]]$Lines) {
    # UTF-8 without BOM: a BOM can make a scoring engine read the header as "\ufeffusername".
    [IO.File]::WriteAllLines($Path, $Lines, (New-Object Text.UTF8Encoding($false)))
}

function Add-Line([string]$Path, [string]$Line) {
    [IO.File]::AppendAllText($Path, $Line + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
}

function Test-Credential($Context, [string]$User, [string]$Password) {
    try { return [bool]$Context.ValidateCredentials($User, $Password, [System.DirectoryServices.AccountManagement.ContextOptions]::Negotiate) }
    catch { return $false }
}

function Get-Candidates {
    # Every account, with an exclusion reason (empty = will be reset).
    $mySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $out = @()
    if ($Local) {
        foreach ($u in @(Get-LocalUser)) {
            $sid = $u.SID.Value
            $locked = $false
            try { $locked = [bool]([ADSI]('WinNT://./{0},user' -f $u.Name)).IsAccountLocked.Value } catch { }
            $out += [pscustomobject]@{ Name = $u.Name; Display = $u.FullName; Sid = $sid; Rid = ($sid -split '-')[-1]; Dn = ''
                                       Enabled = [bool]$u.Enabled; LockedOut = $locked; Spn = $false; Reason = '' }
        }
    } else {
        $p = @{ Filter = '*'; Properties = @('servicePrincipalName', 'LockedOut', 'DisplayName') }
        if ($SearchBase) { $p.SearchBase = $SearchBase }
        foreach ($u in @(Get-ADUser @p)) {
            $sid = $u.SID.Value
            $out += [pscustomobject]@{ Name = $u.SamAccountName; Display = $u.DisplayName; Sid = $sid; Rid = ($sid -split '-')[-1]
                                       Dn = $u.DistinguishedName; Enabled = [bool]$u.Enabled; LockedOut = [bool]$u.LockedOut
                                       Spn = (@($u.servicePrincipalName) | Where-Object { $_ }).Count -gt 0; Reason = '' }
        }
    }
    $builtin = @{ '500' = 'built-in Administrator'; '501' = 'built-in Guest'; '502' = 'krbtgt'; '503' = 'DefaultAccount'; '504' = 'WDAGUtilityAccount' }
    foreach ($c in $out) {
        if ($builtin.ContainsKey([string]$c.Rid)) { $c.Reason = $builtin[[string]$c.Rid] }
        elseif ($c.Name -like 'krbtgt*') { $c.Reason = 'krbtgt (RODC)' }
        elseif ($c.Name.EndsWith('$')) { $c.Reason = 'trust / machine account' }
        elseif ($c.Sid -eq $mySid) { $c.Reason = 'you (running this script)' }
    }
    $out
}

# ---------------------------------------------------------------- main
if ($MyInvocation.InvocationName -eq '.') { return }
if (-not (Test-IsAdmin)) { Write-Bad 'Run this from an elevated PowerShell.'; exit 1 }

$isDC = ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4)
if ($Local -and $isDC) { Write-Bad 'A domain controller has no local accounts. Run without -Local.'; exit 1 }
Add-Type -AssemblyName System.DirectoryServices.AccountManagement

$prefix = $env:COMPUTERNAME
$dc = $null
if ($Local) {
    $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)
    Write-Section ('Local password reset on {0}' -f $env:COMPUTERNAME)
} else {
    try { Import-Module ActiveDirectory -ErrorAction Stop } catch { Write-Bad 'ActiveDirectory module missing (run on the DC, or use -Local on a member server).'; exit 1 }
    $domainObj = Get-ADDomain
    $prefix = $domainObj.NetBIOSName
    if ($isDC) { $dc = $env:COMPUTERNAME } else { $dc = @((Get-ADDomainController -Discover).HostName)[0] }
    $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $dc)
    Write-Section ('Domain password reset in {0} (using DC {1})' -f $domainObj.DNSRoot, $dc)
}

# --- build the list
$all = @(Get-Candidates)
$patterns = @()
foreach ($e in @($Exclude)) { if ($e) { $patterns += (Get-BareName $e) } }
if ($ExcludeFile) {
    if (-not (Test-Path -LiteralPath $ExcludeFile)) { Write-Bad ('Exclude file not found: {0}' -f $ExcludeFile); exit 1 }
    foreach ($line in Get-Content -LiteralPath $ExcludeFile) {
        $l = $line.Trim()
        if ($l -and -not $l.StartsWith('#')) { $patterns += (Get-BareName $l) }
    }
}
$groupMembers = @{}
foreach ($g in @($ExcludeGroup)) {
    if (-not $g) { continue }
    try {
        if ($Local) { $members = @(Get-LocalGroupMember -Group $g -ErrorAction Stop | ForEach-Object { Get-BareName $_.Name }) }
        else { $members = @(Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' } | ForEach-Object { $_.SamAccountName }) }
        foreach ($m in $members) { $groupMembers[$m] = $g }
        Write-Info ('Group "{0}": {1} members excluded' -f $g, $members.Count)
    } catch { Write-Bad ('Could not read group "{0}": {1}' -f $g, $_.Exception.Message); exit 1 }
}

$used = @{}
foreach ($c in $all) {
    if ($c.Reason) { continue }
    if (-not $c.Enabled -and -not $IncludeDisabled) { $c.Reason = 'disabled'; continue }
    foreach ($p in $patterns) {
        if ($c.Name -like $p) { $c.Reason = ('excluded ({0})' -f $p); $used[$p] = $true; break }
    }
    if (-not $c.Reason -and $groupMembers.ContainsKey($c.Name)) { $c.Reason = ('member of {0}' -f $groupMembers[$c.Name]) }
}
foreach ($p in $patterns) { if (-not $used.ContainsKey($p)) { Write-Warn ('Exclude pattern "{0}" matched no account - typo?' -f $p) } }

$targets = @($all | Where-Object { -not $_.Reason } | Sort-Object Name)
$skipped = @($all | Where-Object { $_.Reason })

Write-Section ('Not touched ({0})' -f $skipped.Count)
foreach ($grp in ($skipped | Group-Object Reason | Sort-Object Name)) {
    Write-Info ('{0,-34} {1}' -f $grp.Name, (($grp.Group | ForEach-Object { $_.Name }) -join ', '))
}

Write-Section ('Will be reset ({0})' -f $targets.Count)
if ($targets.Count -eq 0) { Write-Warn 'Nothing to reset.'; return }
Write-Host ((($targets | ForEach-Object { $_.Name }) -join ', '))
$svcLike = @($targets | Where-Object { $_.Spn -or $_.Name -match '(?i)^(svc|srv|sa|service|sql|iis|app|web|backup|bkp|scan|ldap|bind|sync|task)[_\-.]|svc|service' })
if ($svcLike.Count) {
    Write-Warn ('Look like service accounts and WILL be reset (exclude them if they run a service): {0}' -f (($svcLike | ForEach-Object {
        if ($_.Spn) { '{0} (has SPN)' -f $_.Name } else { $_.Name } }) -join ', '))
}
$locked = @($targets | Where-Object { $_.LockedOut })
if ($locked.Count) { Write-Info ('Currently locked out (will be unlocked): {0}' -f (($locked | ForEach-Object { $_.Name }) -join ', ')) }

if ($WhatIfPreference) { Write-Info 'WhatIf: nothing changed and no passwords were written.'; return }

Write-Host ''
Write-Warn ('About to reset {0} passwords. Old passwords cannot be recovered.' -f $targets.Count)
if (-not $Force) {
    $answer = Read-Host 'Type RESET to continue'
    if ($answer -cne 'RESET') { Write-Info 'Cancelled. Nothing changed.'; return }
}

# --- working file first
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$root = Join-Path $OutDir 'passwords'
$runDir = Join-Path $root $stamp
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
Protect-Path $root
Protect-Path $runDir
$workFile = Join-Path $runDir 'WORKING-all-generated.csv'
$resultsFile = Join-Path $runDir 'results.csv'
$submitFile = Join-Path $runDir 'scoring-passwords.csv'

foreach ($t in $targets) {
    $t | Add-Member -NotePropertyName Password -NotePropertyValue (New-RandomPassword -Len $Length -Avoid (Get-NameTokens $t.Name $t.Display)) -Force
}
Write-Lines $workFile (@('username,password') + @($targets | ForEach-Object { '{0},{1}' -f $_.Name, $_.Password }))
Write-Lines $resultsFile @('username,status,detail')
Write-Good ('Working copy of all generated passwords: {0}' -f $workFile)

# --- reset
Write-Section 'Resetting'
$done = New-Object System.Collections.Generic.List[object]
$i = 0
foreach ($t in $targets) {
    $i++
    $set = $false; $err = ''; $notes = @()
    for ($try = 1; $try -le 3 -and -not $set; $try++) {
        $sec = ConvertTo-SecureString $t.Password -AsPlainText -Force
        try {
            if ($Local) { Set-LocalUser -Name $t.Name -Password $sec -ErrorAction Stop }
            else { Set-ADAccountPassword -Identity $t.Dn -Reset -NewPassword $sec -Server $dc -ErrorAction Stop }
            $set = $true
        } catch {
            $err = $_.Exception.Message
            if ($err -match '(?i)complex|length|history|requirement') {
                $t.Password = New-RandomPassword -Len $Length -Avoid (Get-NameTokens $t.Name $t.Display)
                Add-Line $workFile ('{0},{1}' -f $t.Name, $t.Password)   # retry value, newest line wins
            } else { break }
        }
    }
    if (-not $set) {
        Write-Bad ('[{0}/{1}] {2}: reset FAILED - {3}' -f $i, $targets.Count, $t.Name, $err)
        Add-Line $resultsFile ('{0},FAILED,"{1}"' -f $t.Name, ($err -replace '"', "'"))
        continue
    }

    # The scorer can't change a password at logon, and a locked account fails every check.
    if ($Local) {
        try {
            $a = [ADSI]('WinNT://./{0},user' -f $t.Name)
            $a.psbase.InvokeSet('PasswordExpired', 0)
            if ($t.LockedOut) { $a.psbase.InvokeSet('IsAccountLocked', $false) }
            $a.psbase.CommitChanges()
        } catch { $notes += 'could not clear must-change / unlock' }
    } else {
        try { Set-ADUser -Identity $t.Dn -ChangePasswordAtLogon $false -Server $dc -ErrorAction Stop } catch { $notes += 'could not clear must-change flag' }
        if ($t.LockedOut) { try { Unlock-ADAccount -Identity $t.Dn -Server $dc -ErrorAction Stop } catch { $notes += 'could not unlock' } }
    }

    $verified = Test-Credential -Context $ctx -User $t.Name -Password $t.Password
    $status = 'OK'
    if (-not $verified) { $status = 'SET-VERIFY-FAILED'; $notes += 'login test failed (logon hours / workstation restrictions? disabled?)' }
    $done.Add($t)
    Add-Line $resultsFile ('{0},{1},"{2}"' -f $t.Name, $status, ($notes -join '; '))
    if ($verified -and -not $notes.Count) { Write-Good ('[{0}/{1}] {2}' -f $i, $targets.Count, $t.Name) }
    else { Write-Warn ('[{0}/{1}] {2}: password set, but {3}' -f $i, $targets.Count, $t.Name, ($notes -join '; ')) }
}

# --- submission file
$lines = @()
if (-not $NoHeader) { $lines += ('{0}{1}{2}' -f $UserColumn, $Delimiter, $PasswordColumn) }
foreach ($t in $done) {
    $u = $t.Name
    if ($DomainPrefix) { $u = '{0}\{1}' -f $prefix, $t.Name }
    $lines += ('{0}{1}{2}' -f $u, $Delimiter, $t.Password)
}
Write-Lines $submitFile $lines
Remove-Item -LiteralPath $workFile -Force -ErrorAction SilentlyContinue

$failed = $targets.Count - $done.Count
Write-Section 'Done'
Write-Good ('{0} of {1} passwords reset.' -f $done.Count, $targets.Count)
if ($failed) { Write-Bad ('{0} failed - they still have their OLD password and are NOT in the CSV. See {1}' -f $failed, $resultsFile) }
$unverified = @(Get-Content -LiteralPath $resultsFile | Where-Object { $_ -match ',SET-VERIFY-FAILED,' }).Count
if ($unverified) { Write-Warn ('{0} reset but failed the login test - they ARE in the CSV; check them before submitting.' -f $unverified) }
Write-Info ('Submission CSV: {0}' -f $submitFile)
Write-Info ('Results:        {0}' -f $resultsFile)
if (-not $Local) {
    $dcCount = @(Get-ADDomainController -Filter * -ErrorAction SilentlyContinue).Count
    if ($dcCount -gt 1) { Write-Warn ('{0} domain controllers: wait about a minute for replication before the scorer logs in elsewhere.' -f $dcCount) }
}
Write-Warn 'Check the CSV matches the format the ISE asks for, submit it ONCE, then move it off this box or delete it.'
