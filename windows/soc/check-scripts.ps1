<#
.SYNOPSIS
    Syntax-checks every .ps1 in this folder with the real PowerShell parser, then dot-sources each one to
    catch load-time errors. Changes nothing on the machine (each script stops before its main section).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\check-scripts.ps1
#>
$bad = 0
$self = $MyInvocation.MyCommand.Path
foreach ($f in Get-ChildItem -Path $PSScriptRoot -Filter *.ps1) {
    if ($f.FullName -eq $self) { continue }
    $tokens = $null; $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) {
        $bad++
        Write-Host ('[X] {0}: {1} parse error(s)' -f $f.Name, $errors.Count) -ForegroundColor Red
        foreach ($e in $errors) { Write-Host ('    line {0}: {1}' -f $e.Extent.StartLineNumber, $e.Message) -ForegroundColor Red }
        continue
    }
    try {
        # Each script returns right after defining its functions when dot-sourced.
        $null = & { . $f.FullName }
        Write-Host ('[+] {0}' -f $f.Name) -ForegroundColor Green
    } catch {
        $bad++
        Write-Host ('[X] {0}: load error: {1}' -f $f.Name, $_.Exception.Message) -ForegroundColor Red
    }
}
Write-Host ('Checked with PowerShell {0}' -f $PSVersionTable.PSVersion)
if ($bad) { exit 1 }
