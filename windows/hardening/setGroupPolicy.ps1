#Requires -RunAsAdministrator
# setGroupPolicy.ps1 - run on the DC as a Domain Admin.
# Makes two GPOs linked (enforced) to the whole domain: "CCDC Hardening" and "CCDC Logging".
# Turn one off:  Set-GPLink -Name 'CCDC Hardening' -Target (Get-ADDomain).DistinguishedName -LinkEnabled No
# Push now:      gpupdate /force on each box (DCs refresh in ~5 min, other boxes within 2 hours)

Import-Module GroupPolicy, ActiveDirectory
$d   = Get-ADDomain
$dn  = $d.DistinguishedName
$dns = $d.DNSRoot

function Get-OrNewGpo($name) {
    $g = Get-GPO -Name $name -ErrorAction SilentlyContinue
    if (-not $g) { $g = New-GPO -Name $name; New-GPLink -Guid $g.Id -Target $dn -LinkEnabled Yes -Enforced Yes | Out-Null }
    return $g
}
function GpReg($gpo, $key, $name, $value, $type = 'DWord') {
    Set-GPRegistryValue -Guid $gpo.Id -Key $key -ValueName $name -Type $type -Value $value | Out-Null
}
# Writes a non-registry policy file (GptTmpl.inf, used by the commented-out lines) into the GPO and tells AD the GPO changed
function Add-GpoFile($gpo, $relPath, $text, $cse, $encoding) {
    $root = "\\$dns\SYSVOL\$dns\Policies\{$($gpo.Id)}"
    $file = "$root\Machine\$relPath"
    New-Item -ItemType Directory -Force -Path (Split-Path $file) | Out-Null
    Set-Content -Path $file -Value $text -Encoding $encoding
    $o   = Get-ADObject -Identity $gpo.Path -Properties gPCMachineExtensionNames, versionNumber
    $ext = @([regex]::Matches("$($o.gPCMachineExtensionNames)", '\[[^\]]+\]') | ForEach-Object Value) + $cse | Sort-Object -Unique
    $ver = [int]$o.versionNumber + 1
    Set-ADObject -Identity $gpo.Path -Replace @{ gPCMachineExtensionNames = ($ext -join ''); versionNumber = $ver }
    (Get-Content "$root\GPT.INI") -replace 'Version=\d+', "Version=$ver" | Set-Content "$root\GPT.INI" -Encoding ASCII
}

$hard = Get-OrNewGpo 'CCDC Hardening'
$log  = Get-OrNewGpo 'CCDC Logging'

# ---------------- name poisoning (Responder)
GpReg $hard 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' EnableMulticast 0          # LLMNR off
GpReg $hard 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' EnableNetbios 0            # NetBIOS off (Win11 22H2+/Server 2025 only, see notes)
GpReg $hard 'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' EnableMDNS 0          # mDNS off

# ---------------- credential theft and relay
GpReg $hard 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' UseLogonCredential 0   # no clear-text passwords in memory
GpReg $hard 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' RequireSecuritySignature 1   # SMB signing, server
GpReg $hard 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' EnableSecuritySignature 1
GpReg $hard 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' RequireSecuritySignature 1   # SMB signing, client
GpReg $hard 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' EnableSecuritySignature 1
GpReg $hard 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' SMB1 0           # SMBv1 server off
GpReg $hard 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' LmCompatibilityLevel 5                 # NTLMv2 only, refuse LM and NTLMv1
GpReg $hard 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' RestrictAnonymousSAM 1                 # no anonymous account listing
GpReg $hard 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' RestrictAnonymous 1                    # no anonymous account/share listing
GpReg $hard 'HKLM\SYSTEM\CurrentControlSet\Services\Spooler' Start 4                           # Print Spooler disabled (after reboot)
Stop-Service Spooler -Force                                                                   # stop it on this DC now

# ---------------- local admin lateral movement (left OFF on purpose; check the scoring accounts first)
# GpReg $hard 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' LocalAccountTokenFilterPolicy 0
#   undo: GpReg $hard 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' LocalAccountTokenFilterPolicy 1
#
# $inf = '[Unicode]','Unicode=yes','[Version]','signature="$CHICAGO$"','Revision=1','[Privilege Rights]','SeDenyNetworkLogonRight = *S-1-5-114','SeDenyRemoteInteractiveLogonRight = *S-1-5-114' -join "`r`n"
# Add-GpoFile $hard 'Microsoft\Windows NT\SecEdit\GptTmpl.inf' $inf '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]' 'Unicode'
#   undo: $inf = '[Unicode]','Unicode=yes','[Version]','signature="$CHICAGO$"','Revision=1','[Privilege Rights]','SeDenyNetworkLogonRight =','SeDenyRemoteInteractiveLogonRight =' -join "`r`n"; Add-GpoFile $hard 'Microsoft\Windows NT\SecEdit\GptTmpl.inf' $inf '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]' 'Unicode'

# ---------------- Defender: can't be turned off, ignores exclusions added on the box
GpReg $hard 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' DisableAntiSpyware 0
GpReg $hard 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' DisableRealtimeMonitoring 0
GpReg $hard 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' DisableLocalAdminMerge 1
GpReg $hard 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR' ExploitGuard_ASR_Rules 1
GpReg $hard 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' '1' 'String'   # block LSASS credential stealing

# ---------------- LDAP signing: NOT required (keeps plain-text binds like svc_all working)
GpReg $hard 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' LDAPServerIntegrity 1
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' LDAPServerIntegrity 1
#   require it instead: GpReg $hard 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' LDAPServerIntegrity 2; Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' LDAPServerIntegrity 2

# ---------------- logging
GpReg $log 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy 1                                         # detailed audit settings win
GpReg $log 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' ProcessCreationIncludeCmdLine_Enabled 1    # command lines in 4688
GpReg $log 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' EnableScriptBlockLogging 1              # 4104
GpReg $log 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' MaxSize 1048576                                    # 1 GB (value is KB)

# ---------------- accounts
Disable-ADAccount -Identity Guest
Set-ADDefaultDomainPasswordPolicy -Identity $dns -LockoutThreshold 0                         # no lockout
Get-ADFineGrainedPasswordPolicy -Filter * | Set-ADFineGrainedPasswordPolicy -LockoutThreshold 0   # no lockout in fine-grained policies either
Set-ADDomain -Identity $dns -Replace @{ 'ms-DS-MachineAccountQuota' = 0 }                    # normal users can't add computers

gpupdate /force