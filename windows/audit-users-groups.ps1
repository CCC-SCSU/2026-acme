<#
.SYNOPSIS
    Prints the groups every user belongs to and flags dangerous permissions.

.DESCRIPTION
    On a domain controller (or with -Domain and RSAT):
      - Every user: direct groups (incl. primary group) and effective privileged groups (nesting resolved)
      - Risky flags: no password required, AS-REP roastable, reversible encryption, delegation, SPNs,
        SIDHistory, orphaned adminCount, odd primary group, passwords in descriptions, new accounts
      - Computers: non-DCs with delegation/RBCD or in privileged groups
      - Dangerous ACEs (DCSync, GenericAll, WriteDacl, add-member, reset-password, shadow credentials...)
        on the domain root, AdminSDHolder, Domain Controllers OU, privileged groups and privileged users
      - Who can edit GPOs
    On every machine:
      - Local group memberships (member servers)
      - User rights held by unexpected accounts (SeDebug, SeImpersonate, SeBackup, SeLoadDriver...)
      - Auto-logon passwords stored in the registry

    -SaveBaseline records memberships, rights and ACL findings. Later runs diff against it automatically.

.EXAMPLE
    .\audit-users-groups.ps1
.EXAMPLE
    .\audit-users-groups.ps1 -SaveBaseline      # after you've cleaned up; later runs show changes
#>
[CmdletBinding()]
param(
    [string]$OutDir = 'C:\Backup',
    [string]$Baseline,
    [switch]$SaveBaseline,
    [switch]$SkipAcl,
    [switch]$Domain,
    [int]$RecentDays = 7
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
function Get-ItemCount($x) { @($x | Where-Object { $null -ne $_ -and "$_" -ne '' }).Count }
function Get-LevelRank([string]$Level) { switch ($Level) { 'Critical' { 3 } 'High' { 2 } 'Notable' { 1 } default { 0 } } }

$script:SidNameCache = @{}
function Resolve-Sid([string]$Sid) {
    if ($script:SidNameCache.ContainsKey($Sid)) { return $script:SidNameCache[$Sid] }
    $name = $Sid
    try { $name = (New-Object Security.Principal.SecurityIdentifier($Sid)).Translate([Security.Principal.NTAccount]).Value }
    catch { $name = ('{0} (unresolved)' -f $Sid) }
    $script:SidNameCache[$Sid] = $name
    $name
}

function ConvertTo-LdapEscaped([string]$Value) {
    $sb = New-Object Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        switch ($ch) {
            '\' { [void]$sb.Append('\5c') }
            '*' { [void]$sb.Append('\2a') }
            '(' { [void]$sb.Append('\28') }
            ')' { [void]$sb.Append('\29') }
            default { [void]$sb.Append($ch) }
        }
    }
    $sb.ToString()
}

# ---------------------------------------------------------------- user rights
$script:Admins = @('S-1-5-32-544')
$script:SvcSids = @('S-1-5-19', 'S-1-5-20', 'S-1-5-6')
$script:RightRules = [ordered]@{
    'SeDebugPrivilege'                          = $script:Admins
    'SeTcbPrivilege'                            = @()
    'SeCreateTokenPrivilege'                    = @()
    'SeAssignPrimaryTokenPrivilege'             = $script:SvcSids
    'SeImpersonatePrivilege'                    = $script:Admins + $script:SvcSids + @('S-1-5-32-568')
    'SeLoadDriverPrivilege'                     = $script:Admins + @('S-1-5-32-550')
    'SeBackupPrivilege'                         = $script:Admins + @('S-1-5-32-551', 'S-1-5-32-549')
    'SeRestorePrivilege'                        = $script:Admins + @('S-1-5-32-551', 'S-1-5-32-549')
    'SeTakeOwnershipPrivilege'                  = $script:Admins
    'SeSecurityPrivilege'                       = $script:Admins
    'SeSystemEnvironmentPrivilege'              = $script:Admins
    'SeManageVolumePrivilege'                   = $script:Admins
    'SeEnableDelegationPrivilege'               = $script:Admins
    'SeRelabelPrivilege'                        = @()
    'SeTrustedCredManAccessPrivilege'           = @()
    'SeCreateSymbolicLinkPrivilege'             = $script:Admins
    'SeDelegateSessionUserImpersonatePrivilege' = $script:Admins
    'SeRemoteInteractiveLogonRight'             = $script:Admins + @('S-1-5-32-555')
    'SeInteractiveLogonRight'                   = $script:Admins + @('S-1-5-32-545', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550', 'S-1-5-32-551', 'S-1-5-9')
}
# Service/virtual-account SIDs that legitimately hold impersonation rights (SQL, IIS app pools, ...)
$script:VirtualSidPrefixes = @('S-1-5-80-', 'S-1-5-82-', 'S-1-5-83-', 'S-1-5-90-', 'S-1-5-96-', 'S-1-5-99-')

function Test-AllowedRightHolder([string]$Right, [string]$Sid) {
    if (-not $script:RightRules.Contains($Right)) { return $true }
    if ($script:RightRules[$Right] -contains $Sid) { return $true }
    if ($Right -in 'SeImpersonatePrivilege', 'SeAssignPrimaryTokenPrivilege') {
        foreach ($p in $script:VirtualSidPrefixes) { if ($Sid.StartsWith($p)) { return $true } }
    }
    return $false
}

function Get-UserRights {
    $inf = Join-Path $env:TEMP ('ur-{0}.inf' -f [guid]::NewGuid())
    try {
        # /mergedpolicy = local + domain GPO settings (on a DC the rights come from Default Domain Controllers Policy)
        & secedit.exe /export /mergedpolicy /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
        if (-not (Test-Path -LiteralPath $inf)) { Write-Warn 'secedit export failed.'; return }
        $inSection = $false
        foreach ($line in Get-Content -LiteralPath $inf) {
            if ($line -match '^\[(.+)\]') { $inSection = ($Matches[1] -eq 'Privilege Rights'); continue }
            if (-not $inSection) { continue }
            if ($line -notmatch '^\s*(Se\w+)\s*=\s*(.*)$') { continue }
            $priv = $Matches[1]
            $holders = $Matches[2] -split ','
            foreach ($item in $holders) {
                $item = $item.Trim()
                if (-not $item) { continue }
                if ($item.StartsWith('*')) { $sid = $item.Substring(1) }
                else {
                    try { $sid = (New-Object Security.Principal.NTAccount($item)).Translate([Security.Principal.SecurityIdentifier]).Value }
                    catch { $sid = $item }
                }
                [pscustomobject]@{ Right = $priv; Sid = $sid; Name = (Resolve-Sid $sid); Unexpected = -not (Test-AllowedRightHolder $priv $sid) }
            }
        }
    } finally { Remove-Item -LiteralPath $inf -Force -ErrorAction SilentlyContinue }
}

function Get-AutoLogonFinding {
    $p = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
    if ($p -and $p.DefaultPassword) {
        return ('Winlogon DefaultPassword is set for {0}\{1} (AutoAdminLogon={2}): plaintext password in the registry' -f $p.DefaultDomainName, $p.DefaultUserName, $p.AutoAdminLogon)
    }
    $null
}

# ---------------------------------------------------------------- AD ACL analysis
$script:GuidAll = '00000000-0000-0000-0000-000000000000'
$script:GuidMember = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
$script:DangerousAttrs = @{
    'bf9679c0-0de6-11d0-a285-00aa003049e2' = 'member (add anyone to the group)'
    '5b47d60f-6090-40b2-9f37-2a4de88f3063' = 'msDS-KeyCredentialLink (shadow credentials)'
    'f3a64788-5306-11d1-a9c5-0000f80367c1' = 'servicePrincipalName (targeted kerberoast)'
    '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' = 'msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)'
    'f30e3bbe-9ff0-11d1-b603-0000f80367c1' = 'gPLink (link a GPO)'
    'bf9679a8-0de6-11d0-a285-00aa003049e2' = 'scriptPath (logon script)'
    'bf967a68-0de6-11d0-a285-00aa003049e2' = 'userAccountControl'
}
$script:DangerousExtRights = @{
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes (DCSync part 1)'
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All (DCSync)'
    '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
    '00299570-246d-11d0-a768-00aa006e0529' = 'Reset password without knowing it'
}
$script:SchemaNames = @{
    'bf967aba-0de6-11d0-a285-00aa003049e2' = 'user'
    'bf967a9c-0de6-11d0-a285-00aa003049e2' = 'group'
    'bf967a86-0de6-11d0-a285-00aa003049e2' = 'computer'
    '4828cc14-1437-45bc-9b07-ad6f015e5f28' = 'inetOrgPerson'
    'bf967aa5-0de6-11d0-a285-00aa003049e2' = 'organizationalUnit'
    'f30e3bc2-9ff0-11d1-b603-0000f80367c1' = 'groupPolicyContainer'
    '7b8b558a-93a5-4af7-adca-c017e67f1057' = 'gMSA'
}

function Get-AceRisk {
    param([int]$Rights, [string]$ObjectType)
    # Raw ADS rights bits, so this works without loading System.DirectoryServices types.
    $GenericAll = 0xF01FF; $GenericWrite = 0x20028
    $WriteDacl = 0x40000; $WriteOwner = 0x80000; $WriteProp = 0x20; $ExtRight = 0x100; $Self = 0x8
    $ot = $ObjectType.ToLowerInvariant()
    $all = ($ot -eq $script:GuidAll)
    $hits = @()
    if (($Rights -band $GenericAll) -eq $GenericAll) { return 'GenericAll (full control)' }
    if ($Rights -band $WriteDacl) { $hits += 'WriteDacl' }
    if ($Rights -band $WriteOwner) { $hits += 'WriteOwner' }
    if ($all -and (($Rights -band $GenericWrite) -eq $GenericWrite)) { $hits += 'GenericWrite' }
    elseif ($Rights -band $WriteProp) {
        if ($all) { $hits += 'WriteProperty (all attributes)' }
        elseif ($script:DangerousAttrs.ContainsKey($ot)) { $hits += ('Write ' + $script:DangerousAttrs[$ot]) }
    }
    if ($Rights -band $ExtRight) {
        if ($all) { $hits += 'AllExtendedRights (reset password / DCSync)' }
        elseif ($script:DangerousExtRights.ContainsKey($ot)) { $hits += $script:DangerousExtRights[$ot] }
    }
    if (($Rights -band $Self) -and -not (($Rights -band $GenericWrite) -eq $GenericWrite)) {
        if ($all -or $ot -eq $script:GuidMember) { $hits += 'Add self to group' }
    }
    if ($hits.Count -eq 0) { return $null }
    $hits -join ', '
}

function Get-DangerousAces {
    param([string]$ObjectDn, [string]$Label, [hashtable]$SafeSids)
    try { $acl = Get-Acl -Path ('AD:{0}' -f $ObjectDn) -ErrorAction Stop }
    catch { Write-Warn ('Could not read ACL on {0}' -f $Label); return }
    foreach ($ace in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ([string]$ace.AccessControlType -ne 'Allow') { continue }
        $sid = $ace.IdentityReference.Value
        if ($SafeSids.ContainsKey($sid)) { continue }
        $what = Get-AceRisk -Rights ([int]$ace.ActiveDirectoryRights) -ObjectType $ace.ObjectType.ToString()
        if (-not $what) { continue }
        $scope = 'this object'
        if (([int]$ace.PropagationFlags -band 2) -ne 0) { $scope = 'child objects only' }   # InheritOnly
        $iot = $ace.InheritedObjectType.ToString().ToLowerInvariant()
        if ($iot -ne $script:GuidAll) {
            $tn = $iot
            if ($script:SchemaNames.ContainsKey($iot)) { $tn = $script:SchemaNames[$iot] }
            $scope += (' (' + $tn + ' objects)')
        }
        [pscustomobject]@{ Object = $Label; Trustee = (Resolve-Sid $sid); TrusteeSid = $sid; Right = $what; Scope = $scope; Inherited = $ace.IsInherited }
    }
}

function Get-EffectiveMembers($Group, [string]$DomainSid) {
    $filter = '(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={0}))' -f (ConvertTo-LdapEscaped $Group.DistinguishedName)
    $members = @(Get-ADObject -LDAPFilter $filter -Properties sAMAccountName, objectSid, primaryGroupID)
    $sid = $Group.SID.Value
    if ($sid.StartsWith($DomainSid + '-')) {
        $rid = ($sid -split '-')[-1]
        $members += @(Get-ADObject -LDAPFilter ('(&(objectClass=user)(primaryGroupID={0}))' -f $rid) -Properties sAMAccountName, objectSid, primaryGroupID)
    }
    $members | Sort-Object DistinguishedName -Unique
}

function Invoke-ADAudit {
    Import-Module ActiveDirectory -ErrorAction Stop
    $domainObj = Get-ADDomain
    $dn = $domainObj.DistinguishedName
    $dsid = $domainObj.DomainSID.Value
    $rootSid = $dsid
    try { $rootSid = (Get-ADDomain -Identity (Get-ADForest).RootDomain).DomainSID.Value } catch { }

    $allGroups = @(Get-ADGroup -Filter *)
    $groupByDn = @{}; $groupBySid = @{}
    foreach ($g in $allGroups) { $groupByDn[$g.DistinguishedName] = $g; $groupBySid[$g.SID.Value] = $g }

    $privDefs = @(
        @{ Sid = "$dsid-512"; Level = 'Critical' }, @{ Sid = "$rootSid-519"; Level = 'Critical' },
        @{ Sid = "$rootSid-518"; Level = 'Critical' }, @{ Sid = 'S-1-5-32-544'; Level = 'Critical' },
        @{ Sid = "$dsid-516"; Level = 'Critical' },
        @{ Sid = 'S-1-5-32-548'; Level = 'High' }, @{ Sid = 'S-1-5-32-551'; Level = 'High' },
        @{ Sid = 'S-1-5-32-549'; Level = 'High' }, @{ Sid = 'S-1-5-32-550'; Level = 'High' },
        @{ Sid = "$dsid-520"; Level = 'High' }, @{ Sid = "$dsid-526"; Level = 'High' },
        @{ Sid = "$rootSid-527"; Level = 'High' }, @{ Sid = 'S-1-5-32-578'; Level = 'High' },
        @{ Sid = 'S-1-5-32-555'; Level = 'Notable' }, @{ Sid = 'S-1-5-32-580'; Level = 'Notable' },
        @{ Sid = 'S-1-5-32-562'; Level = 'Notable' }
    )
    $privGroups = @()
    foreach ($d in $privDefs) { if ($groupBySid.ContainsKey($d.Sid)) { $privGroups += [pscustomobject]@{ Group = $groupBySid[$d.Sid]; Level = $d.Level } } }
    foreach ($g in $allGroups) { if ($g.Name -eq 'DnsAdmins') { $privGroups += [pscustomobject]@{ Group = $g; Level = 'High' } } }

    $dcDns = @{}
    foreach ($dc in @(Get-ADDomainController -Filter *)) { $dcDns[$dc.ComputerObjectDN] = $true }

    Write-Info 'Resolving privileged group membership (nested groups included)...'
    $privByDn = @{}; $levelByDn = @{}; $privRows = @()
    foreach ($pg in $privGroups) {
        $members = @(Get-EffectiveMembers -Group $pg.Group -DomainSid $dsid)
        if ($members.Count -eq 0) {
            $privRows += [pscustomobject]@{ Group = $pg.Group.Name; Level = $pg.Level; Member = '(empty)'; Class = ''; Expected = $true }
        }
        foreach ($m in $members) {
            $msid = $m.objectSid.Value
            $expected = ($msid -eq "$dsid-500")
            if ($pg.Group.SID.Value -eq "$dsid-516" -and $dcDns.ContainsKey($m.DistinguishedName)) { $expected = $true }
            if ($pg.Level -eq 'Notable') { $expected = $true }
            $privRows += [pscustomobject]@{ Group = $pg.Group.Name; Level = $pg.Level; Member = $m.sAMAccountName; Class = $m.ObjectClass; Expected = $expected }
            if (-not $privByDn.ContainsKey($m.DistinguishedName)) { $privByDn[$m.DistinguishedName] = New-Object System.Collections.Generic.List[string] }
            $privByDn[$m.DistinguishedName].Add($pg.Group.Name)
            if ((Get-LevelRank $pg.Level) -gt (Get-LevelRank $levelByDn[$m.DistinguishedName])) { $levelByDn[$m.DistinguishedName] = $pg.Level }
        }
    }

    Write-Info 'Reading users...'
    $props = 'memberOf', 'primaryGroupID', 'adminCount', 'servicePrincipalName', 'sIDHistory', 'msDS-AllowedToDelegateTo',
             'description', 'whenCreated', 'PasswordNeverExpires', 'PasswordNotRequired', 'DoesNotRequirePreAuth',
             'AllowReversiblePasswordEncryption', 'TrustedForDelegation', 'TrustedToAuthForDelegation'
    $userRows = @()
    $recent = (Get-Date).AddDays(-$RecentDays)
    foreach ($u in @(Get-ADUser -Filter * -Properties $props)) {
        $direct = New-Object System.Collections.Generic.List[string]
        foreach ($g in @($u.memberOf)) {
            if (-not $g) { continue }
            if ($groupByDn.ContainsKey($g)) { $direct.Add($groupByDn[$g].Name) } else { $direct.Add((($g -split ',')[0] -replace '^CN=', '')) }
        }
        $pgKey = '{0}-{1}' -f $dsid, $u.primaryGroupID
        if ($groupBySid.ContainsKey($pgKey)) { $direct.Add(('{0} (primary)' -f $groupBySid[$pgKey].Name)) }
        $level = ''; $privList = ''
        if ($privByDn.ContainsKey($u.DistinguishedName)) {
            $level = $levelByDn[$u.DistinguishedName]
            $privList = (@($privByDn[$u.DistinguishedName]) | Select-Object -Unique) -join ', '
        }
        $isPriv = ((Get-LevelRank $level) -ge 2)
        $flags = @()
        if ($u.SamAccountName -eq 'Guest' -and $u.Enabled) { $flags += 'Guest is ENABLED' }
        if ($u.PasswordNotRequired) { $flags += 'no password required' }
        if ($u.DoesNotRequirePreAuth) { $flags += 'AS-REP roastable (no Kerberos preauth)' }
        if ($u.AllowReversiblePasswordEncryption) { $flags += 'reversible password encryption' }
        if ($u.TrustedForDelegation) { $flags += 'unconstrained delegation' }
        if ($u.TrustedToAuthForDelegation) { $flags += 'protocol transition delegation' }
        if ((Get-ItemCount $u.'msDS-AllowedToDelegateTo') -gt 0) { $flags += ('constrained delegation to ' + (@($u.'msDS-AllowedToDelegateTo') -join ',')) }
        if ((Get-ItemCount $u.servicePrincipalName) -gt 0 -and $u.SamAccountName -ne 'krbtgt') { $flags += 'has SPN (kerberoastable)' }
        if ((Get-ItemCount $u.sIDHistory) -gt 0) { $flags += 'SIDHistory set' }
        if ($u.adminCount -eq 1 -and -not $isPriv -and $u.SamAccountName -ne 'krbtgt') { $flags += 'adminCount=1 but no privileged group (removed admin? check ACL)' }
        if ($u.primaryGroupID -and ($u.primaryGroupID -notin 513, 514)) { $flags += ('primary group RID {0}' -f $u.primaryGroupID) }
        if ($u.description -match '(?i)pass|pwd|p/w|cred|secret') { $flags += 'description may contain a password' }
        if ($u.whenCreated -gt $recent) { $flags += ('created {0}' -f $u.whenCreated) }
        if ($u.PasswordNeverExpires -and $isPriv) { $flags += 'admin password never expires' }
        $userRows += [pscustomobject]@{
            User = $u.SamAccountName; Enabled = [bool]$u.Enabled; Level = $level; PrivilegedGroups = $privList
            DirectGroups = (@($direct) -join ', '); Flags = ($flags -join '; '); Groups = @($direct | Sort-Object)
        }
    }

    Write-Info 'Reading computers...'
    $compRows = @()
    $cprops = 'TrustedForDelegation', 'TrustedToAuthForDelegation', 'msDS-AllowedToDelegateTo', 'PrincipalsAllowedToDelegateToAccount', 'primaryGroupID', 'whenCreated', 'OperatingSystem'
    foreach ($c in @(Get-ADComputer -Filter * -Properties $cprops)) {
        $isDcObj = $dcDns.ContainsKey($c.DistinguishedName)
        $flags = @()
        if (-not $isDcObj) {
            if ($c.TrustedForDelegation) { $flags += 'unconstrained delegation (non-DC)' }
            if ($c.primaryGroupID -in 516, 521) { $flags += 'primary group is Domain Controllers but it is not a DC' }
        }
        if ($c.TrustedToAuthForDelegation) { $flags += 'protocol transition delegation' }
        if ((Get-ItemCount $c.'msDS-AllowedToDelegateTo') -gt 0) { $flags += ('constrained delegation to ' + (@($c.'msDS-AllowedToDelegateTo') -join ',')) }
        if ((Get-ItemCount $c.PrincipalsAllowedToDelegateToAccount) -gt 0) { $flags += ('RBCD from ' + (@($c.PrincipalsAllowedToDelegateToAccount) -join ',')) }
        if ($privByDn.ContainsKey($c.DistinguishedName) -and -not $isDcObj) { $flags += ('in privileged groups: ' + (@($privByDn[$c.DistinguishedName]) -join ', ')) }
        if ($c.whenCreated -gt $recent) { $flags += ('created {0}' -f $c.whenCreated) }
        if ($flags.Count) { $compRows += [pscustomobject]@{ Computer = $c.Name; OS = $c.OperatingSystem; IsDC = $isDcObj; Flags = ($flags -join '; ') } }
    }

    $maq = $null
    try { $maq = (Get-ADObject -Identity $dn -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota' } catch { }

    $aclRows = @()
    if (-not $SkipAcl) {
        Write-Info 'Checking ACLs on sensitive objects...'
        $safe = @{}
        foreach ($s in @('S-1-5-18', 'S-1-5-10', 'S-1-3-0', 'S-1-5-32-544', 'S-1-5-9', 'S-1-5-32-548', 'S-1-5-32-560', 'S-1-5-32-561',
                         "$dsid-512", "$dsid-516", "$dsid-517", "$dsid-521", "$dsid-526",
                         "$rootSid-498", "$rootSid-518", "$rootSid-519", "$rootSid-527")) { $safe[$s] = $true }
        $targets = [ordered]@{}
        $targets['Domain root'] = $dn
        $targets['AdminSDHolder'] = "CN=AdminSDHolder,CN=System,$dn"
        $targets['Domain Controllers OU'] = $domainObj.DomainControllersContainer
        foreach ($pg in $privGroups) { $targets[('Group: {0}' -f $pg.Group.Name)] = $pg.Group.DistinguishedName }
        foreach ($k in $privByDn.Keys) {
            if ((Get-LevelRank $levelByDn[$k]) -ge 2) { $targets[('Privileged account: {0}' -f (($k -split ',')[0] -replace '^CN=', ''))] = $k }
        }
        foreach ($label in $targets.Keys) { $aclRows += @(Get-DangerousAces -ObjectDn $targets[$label] -Label $label -SafeSids $safe) }

        try {
            Import-Module GroupPolicy -ErrorAction Stop
            $gpSafe = @("$dsid-512", "$rootSid-519", 'S-1-5-18', "$dsid-500", 'S-1-5-9', 'S-1-3-0')
            foreach ($gpo in @(Get-GPO -All)) {
                foreach ($p in @(Get-GPPermission -Guid $gpo.Id -All -ErrorAction SilentlyContinue)) {
                    if ([string]$p.Permission -notmatch 'Edit|Custom') { continue }
                    $sid = $p.Trustee.Sid.Value
                    if ($gpSafe -contains $sid) { continue }
                    $aclRows += [pscustomobject]@{ Object = ('GPO: {0}' -f $gpo.DisplayName); Trustee = (Resolve-Sid $sid); TrusteeSid = $sid; Right = [string]$p.Permission; Scope = 'GPO'; Inherited = $false }
                }
            }
        } catch { Write-Warn 'GroupPolicy module not available - GPO edit rights not checked.' }
    }

    [pscustomobject]@{ Users = $userRows; Privileged = $privRows; Computers = $compRows; Acl = $aclRows; MachineAccountQuota = $maq }
}

# ---------------------------------------------------------------- local accounts
function Get-LocalGroupMembersSafe([string]$Group) {
    try {
        return @(Get-LocalGroupMember -Group $Group -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; Sid = $_.SID.Value; Class = [string]$_.ObjectClass } })
    } catch {
        # Get-LocalGroupMember breaks on orphaned SIDs; fall back to ADSI.
        $out = @()
        try {
            $g = [ADSI]('WinNT://./{0},group' -f $Group)
            foreach ($m in @($g.psbase.Invoke('Members'))) {
                $path = $m.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $m, $null)
                $bytes = $m.GetType().InvokeMember('objectSid', 'GetProperty', $null, $m, $null)
                $sid = (New-Object Security.Principal.SecurityIdentifier($bytes, 0)).Value
                $out += [pscustomobject]@{ Name = (($path -replace '^WinNT://', '') -replace '/', '\'); Sid = $sid; Class = '' }
            }
        } catch { }
        return $out
    }
}

function Invoke-LocalAudit {
    $privLocal = @{
        'S-1-5-32-544' = 'Critical'; 'S-1-5-32-551' = 'High'; 'S-1-5-32-578' = 'High'; 'S-1-5-32-547' = 'High'
        'S-1-5-32-555' = 'Notable'; 'S-1-5-32-580' = 'Notable'; 'S-1-5-32-562' = 'Notable'; 'S-1-5-32-556' = 'Notable'
    }
    $memberOf = @{}; $privRows = @(); $levelByName = @{}
    foreach ($g in @(Get-LocalGroup)) {
        $gsid = $g.SID.Value
        foreach ($m in @(Get-LocalGroupMembersSafe $g.Name)) {
            if (-not $memberOf.ContainsKey($m.Name)) { $memberOf[$m.Name] = New-Object System.Collections.Generic.List[string] }
            $memberOf[$m.Name].Add($g.Name)
            if ($privLocal.ContainsKey($gsid)) {
                $expected = ($m.Sid -match '-500$') -or ($m.Sid -match '-512$') -or ($privLocal[$gsid] -eq 'Notable')
                $privRows += [pscustomobject]@{ Group = $g.Name; Level = $privLocal[$gsid]; Member = $m.Name; Class = $m.Class; Expected = $expected }
                if ((Get-LevelRank $privLocal[$gsid]) -gt (Get-LevelRank $levelByName[$m.Name])) { $levelByName[$m.Name] = $privLocal[$gsid] }
            }
        }
    }
    $userRows = @()
    foreach ($u in @(Get-LocalUser)) {
        $full = '{0}\{1}' -f $env:COMPUTERNAME, $u.Name
        $groups = @()
        if ($memberOf.ContainsKey($full)) { $groups = @($memberOf[$full]) }
        $flags = @()
        if ($u.Name -in 'Guest', 'WDAGUtilityAccount', 'DefaultAccount' -and $u.Enabled) { $flags += ('{0} is ENABLED' -f $u.Name) }
        if (-not $u.PasswordRequired) { $flags += 'no password required' }
        if ($u.Enabled -and -not $u.PasswordExpires -and $groups -contains 'Administrators') { $flags += 'admin password never expires' }
        if ($u.Description -match '(?i)pass|pwd|p/w|cred|secret') { $flags += 'description may contain a password' }
        $level = ''
        if ($levelByName.ContainsKey($full)) { $level = $levelByName[$full] }
        $userRows += [pscustomobject]@{
            User = $u.Name; Enabled = [bool]$u.Enabled; Level = $level; PrivilegedGroups = ''
            DirectGroups = ($groups -join ', '); Flags = ($flags -join '; '); Groups = @($groups | Sort-Object)
        }
    }
    [pscustomobject]@{ Users = $userRows; Privileged = $privRows; Computers = @(); Acl = @(); MachineAccountQuota = $null }
}

# ---------------------------------------------------------------- baseline
function New-Snapshot($Audit, $Rights) {
    [pscustomobject]@{
        Created    = (Get-Date).ToString('s')
        Computer   = $env:COMPUTERNAME
        Users      = @($Audit.Users | ForEach-Object { [pscustomobject]@{ Name = $_.User; Enabled = $_.Enabled; Groups = @($_.Groups) } })
        Privileged = @($Audit.Privileged | ForEach-Object { '{0}|{1}' -f $_.Group, $_.Member })
        Rights     = @($Rights | ForEach-Object { '{0}|{1}' -f $_.Right, $_.Sid })
        Acl        = @($Audit.Acl | ForEach-Object { '{0}|{1}|{2}' -f $_.Object, $_.TrusteeSid, $_.Right })
    }
}

function Compare-Snapshot($Old, $New) {
    $changes = @()
    $oldUsers = @{}; foreach ($u in @($Old.Users)) { $oldUsers[$u.Name] = $u }
    $newUsers = @{}; foreach ($u in @($New.Users)) { $newUsers[$u.Name] = $u }
    foreach ($n in $newUsers.Keys) {
        if (-not $oldUsers.ContainsKey($n)) { $changes += [pscustomobject]@{ Change = 'USER ADDED'; Item = $n; Detail = (@($newUsers[$n].Groups) -join ', ') }; continue }
        $og = @($oldUsers[$n].Groups); $ng = @($newUsers[$n].Groups)
        foreach ($g in $ng) { if ($og -notcontains $g) { $changes += [pscustomobject]@{ Change = 'GROUP ADDED'; Item = $n; Detail = $g } } }
        foreach ($g in $og) { if ($ng -notcontains $g) { $changes += [pscustomobject]@{ Change = 'group removed'; Item = $n; Detail = $g } } }
        if ([bool]$oldUsers[$n].Enabled -ne [bool]$newUsers[$n].Enabled) { $changes += [pscustomobject]@{ Change = 'ENABLED CHANGED'; Item = $n; Detail = ('now {0}' -f $newUsers[$n].Enabled) } }
    }
    foreach ($n in $oldUsers.Keys) { if (-not $newUsers.ContainsKey($n)) { $changes += [pscustomobject]@{ Change = 'user removed'; Item = $n; Detail = '' } } }
    foreach ($pair in @(@('Privileged', 'PRIVILEGED MEMBER'), @('Rights', 'USER RIGHT'), @('Acl', 'ACL ENTRY'))) {
        $o = @($Old.($pair[0])); $nw = @($New.($pair[0]))
        foreach ($x in $nw) { if ($o -notcontains $x) { $changes += [pscustomobject]@{ Change = ($pair[1] + ' ADDED'); Item = $x; Detail = '' } } }
        foreach ($x in $o) { if ($nw -notcontains $x) { $changes += [pscustomobject]@{ Change = ($pair[1].ToLower() + ' removed'); Item = $x; Detail = '' } } }
    }
    $changes
}

# ---------------------------------------------------------------- main
if ($MyInvocation.InvocationName -eq '.') { return }
if (-not (Test-IsAdmin)) { Write-Bad 'Run this from an elevated PowerShell.'; exit 1 }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportDir = Join-Path $OutDir ('reports\users-groups-{0}' -f $stamp)
$baselineDir = Join-Path $OutDir 'baselines'
New-Item -ItemType Directory -Path $reportDir, $baselineDir -Force | Out-Null
try { Start-Transcript -Path (Join-Path $reportDir 'transcript.txt') -Force | Out-Null } catch { }

try {
    $isDC = ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4)
    $mode = 'Local'
    if ($isDC -or $Domain) { $mode = 'AD' }
    Write-Section ('User and group audit on {0} ({1} mode)' -f $env:COMPUTERNAME, $mode)

    if ($mode -eq 'AD') { $audit = Invoke-ADAudit } else { $audit = Invoke-LocalAudit }
    $rights = @(Get-UserRights)

    Write-Section 'Every user and their groups (privileged first)'
    $sorted = $audit.Users | Sort-Object -Property @{ Expression = { Get-LevelRank $_.Level }; Descending = $true }, @{ Expression = { $_.User }; Descending = $false }
    foreach ($u in $sorted) {
        $color = 'Gray'
        switch ($u.Level) { 'Critical' { $color = 'Red' } 'High' { $color = 'Magenta' } 'Notable' { $color = 'Cyan' } }
        $state = 'enabled'
        if (-not $u.Enabled) { $state = 'disabled' }
        $tag = ''
        if ($u.Level) { $tag = ('[{0}] ' -f $u.Level.ToUpper()) }
        Write-Host ('{0}{1,-24} {2,-9} {3}' -f $tag, $u.User, $state, $u.DirectGroups) -ForegroundColor $color
        if ($u.PrivilegedGroups) { Write-Host ('      effective privileged groups: {0}' -f $u.PrivilegedGroups) -ForegroundColor $color }
        if ($u.Flags) { Write-Host ('      flags: {0}' -f $u.Flags) -ForegroundColor Yellow }
    }

    Write-Section 'Privileged groups'
    foreach ($grp in ($audit.Privileged | Group-Object Group)) {
        $first = $grp.Group[0]
        $names = @($grp.Group | ForEach-Object { if ($_.Expected) { $_.Member } else { ('{0} <-- CHECK' -f $_.Member) } })
        $bad = @($grp.Group | Where-Object { -not $_.Expected }).Count
        $line = ('{0,-30} [{1}] {2}' -f $grp.Name, $first.Level, ($names -join ', '))
        if ($bad -gt 0) { Write-Bad $line } else { Write-Info $line }
    }

    if (@($audit.Computers).Count) {
        Write-Section 'Computers with risky settings'
        foreach ($c in $audit.Computers) { Write-Bad ('{0} ({1}): {2}' -f $c.Computer, $c.OS, $c.Flags) }
    }
    if ($null -ne $audit.MachineAccountQuota) {
        if ([int]$audit.MachineAccountQuota -gt 0) { Write-Warn ('MachineAccountQuota = {0}: any domain user can add computers (set it to 0).' -f $audit.MachineAccountQuota) }
        else { Write-Good 'MachineAccountQuota = 0' }
    }

    if (-not $SkipAcl -and $mode -eq 'AD') {
        Write-Section 'Dangerous permissions in AD (non-default trustees)'
        if (@($audit.Acl).Count -eq 0) { Write-Good 'None found.' }
        foreach ($a in ($audit.Acl | Sort-Object Object, Trustee)) {
            Write-Bad ('{0}: {1} has {2} [{3}]' -f $a.Object, $a.Trustee, $a.Right, $a.Scope)
        }
    }

    Write-Section 'User rights held by unexpected accounts'
    $odd = @($rights | Where-Object { $_.Unexpected })
    if ($odd.Count -eq 0) { Write-Good 'None found.' }
    foreach ($r in $odd) { Write-Bad ('{0,-34} {1}' -f $r.Right, $r.Name) }
    $machineAcct = @($rights | Where-Object { $_.Right -eq 'SeMachineAccountPrivilege' })
    if ($machineAcct.Count) { Write-Info ('SeMachineAccountPrivilege (add computers to domain): {0}' -f (($machineAcct | ForEach-Object { $_.Name }) -join ', ')) }

    $autologon = Get-AutoLogonFinding
    if ($autologon) { Write-Section 'Stored credentials'; Write-Bad $autologon }

    # reports
    $audit.Users | Select-Object User, Enabled, Level, PrivilegedGroups, DirectGroups, Flags | Export-Csv (Join-Path $reportDir 'users.csv') -NoTypeInformation -Encoding UTF8
    $audit.Privileged | Export-Csv (Join-Path $reportDir 'privileged-groups.csv') -NoTypeInformation -Encoding UTF8
    $rights | Export-Csv (Join-Path $reportDir 'user-rights.csv') -NoTypeInformation -Encoding UTF8
    if (@($audit.Acl).Count) { $audit.Acl | Export-Csv (Join-Path $reportDir 'acl-findings.csv') -NoTypeInformation -Encoding UTF8 }
    if (@($audit.Computers).Count) { $audit.Computers | Export-Csv (Join-Path $reportDir 'computers.csv') -NoTypeInformation -Encoding UTF8 }

    # baseline
    $snap = New-Snapshot -Audit $audit -Rights $rights
    $defaultBaseline = Join-Path $baselineDir 'users-groups.json'
    if (-not $Baseline -and -not $SaveBaseline -and (Test-Path -LiteralPath $defaultBaseline)) { $Baseline = $defaultBaseline }
    if ($Baseline) {
        Write-Section ('Changes since baseline {0}' -f $Baseline)
        $old = Get-Content -LiteralPath $Baseline -Raw | ConvertFrom-Json
        Write-Info ('Baseline taken {0} on {1}' -f $old.Created, $old.Computer)
        $changes = @(Compare-Snapshot -Old $old -New $snap)
        if ($changes.Count -eq 0) { Write-Good 'No changes.' }
        foreach ($c in $changes) {
            $line = ('{0,-22} {1} {2}' -f $c.Change, $c.Item, $c.Detail)
            if ($c.Change -cmatch '^[A-Z ]+$') { Write-Bad $line } else { Write-Info $line }
        }
        $changes | Export-Csv (Join-Path $reportDir 'changes-since-baseline.csv') -NoTypeInformation -Encoding UTF8
    }
    if ($SaveBaseline) {
        $snap | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $defaultBaseline -Encoding UTF8
        Copy-Item -LiteralPath $defaultBaseline -Destination (Join-Path $baselineDir ('users-groups-{0}.json' -f $stamp))
        Write-Good ('Baseline saved: {0}' -f $defaultBaseline)
    }

    Write-Section 'Done'
    Write-Info ('Reports: {0}' -f $reportDir)
} finally {
    try { Stop-Transcript | Out-Null } catch { }
}
