#Requires -RunAsAdministrator
# Run on the DC. Turns off account settings that make passwords easy to steal or crack,
# and saves a list of what it changed (for undoing, and for the incident report). Safe to re-run any time:
# red teams turn these back on.
#
#   No Kerberos preauth     Anyone can ask the DC for a piece of the account's password hash and crack it
#                           offline (AS-REP roasting).
#   Password not required   The account is allowed to have a blank password.
#   Reversible encryption   The DC stores the password in a form that can be turned back into the password.
#   DES only                Forces the weakest Kerberos encryption, which cracks fast.
#
# Run in an admin PowerShell:  powershell -ExecutionPolicy Bypass -File .\fix_account_flags.ps1

Import-Module ActiveDirectory
New-Item -ItemType Directory -Path C:\ccdc -Force | Out-Null
$log = "C:\ccdc\account_flags_$(Get-Date -Format yyyyMMdd_HHmmss).csv"

# Each setting is one bit in userAccountControl. One search per bit finds users, computers and service accounts.
$checks = @(
    @{ Name = 'No Kerberos preauth';   Bit = 4194304; Off = @{ DoesNotRequirePreAuth = $false } }
    @{ Name = 'Password not required'; Bit = 32;      Off = @{ PasswordNotRequired = $false } }
    @{ Name = 'Reversible encryption'; Bit = 128;     Off = @{ AllowReversiblePasswordEncryption = $false } }
    @{ Name = 'DES only';              Bit = 2097152; Off = @{ UseDESKeyOnly = $false } }
)

$changes = foreach ($c in $checks) {
    $found = @(Get-ADObject -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=$($c.Bit))" -Properties sAMAccountName, userAccountControl)
    foreach ($a in $found) {
        $off = $c.Off
        $enabled = -not ($a.userAccountControl -band 2)
        try {
            Set-ADAccountControl -Identity $a.DistinguishedName @off -ErrorAction Stop
            $result = 'fixed'
            Write-Host "Fixed:       $($a.sAMAccountName)  ($($c.Name))" -ForegroundColor Yellow
        } catch {
            $result = "NOT fixed: $($_.Exception.Message)"
            Write-Host "NOT fixed:   $($a.sAMAccountName)  ($($c.Name)): $($_.Exception.Message)" -ForegroundColor Red
        }
        if ($c.Bit -eq 32 -and $enabled) {
            Write-Host "             Reset $($a.sAMAccountName)'s password too. Clearing this setting doesn't remove a blank password it already has." -ForegroundColor Red
        }
        [pscustomobject]@{ Time = (Get-Date); Account = $a.sAMAccountName; Type = $a.ObjectClass; Enabled = $enabled
                           Setting = $c.Name; Result = $result; DN = $a.DistinguishedName }
    }
}

if (@($changes).Count -eq 0) {
    Write-Host 'Nothing to fix: no account has any of these settings turned on.' -ForegroundColor Green
} else {
    $changes | Export-Csv $log -NoTypeInformation
    Write-Host "`nSaved what changed to $log" -ForegroundColor Green
    Write-Host 'If a service breaks, turn the setting back on for just that account, e.g.:'
    Write-Host '   Set-ADAccountControl <account> -DoesNotRequirePreAuth $true'
}