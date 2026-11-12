# point this at where the actual conf file is stored
$dir = "C:Program Files\SplunkUniversalForwarder\etc\apps\ccdc_inputs\local"
# like really, you'll totally need to change this

New-Item -ItemType Directory -Path $dir -Force | Out-Null

conf = @'
[WinEventLog://Security]
disabled = 0
renderXml = false
# Optional noise filter. List only event IDs you've confirmed are noise. Never filter 4624/4625/4688/4720/4728/4732/4740/4769.
# blacklist3 = EventCode="^(4689|4703|4656|4658|4690|5156|5158|4627)$"

[WinEventLog://System]
disabled = 0
renderXml = false

[WinEventLog://Application]
disabled = 0
renderXml = false

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
renderXml = false

[WinEventLog://Microsoft-Windows-WinRM/Operational]
disabled = 0
renderXml = false

[WinEventLog://Microsoft-Windows-Windows Defender/Operational]
disabled = 0
renderXml = false

# Sysmon is sent as XML; install the Splunk Add-on for Sysmon on the Splunk server.
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = true
'@

Set-Content -Path "$dir\inputs.conf" -Value $conf -Encoding ASCII
Restart-Service SplunkForwarder