# Ensure MapleWood-WiFi-User is published on the CA and the CA service can issue it.
$ErrorActionPreference = 'Stop'
Import-Module ADCSAdministration
$name = 'MapleWood-WiFi-User'
if (((Get-CATemplate | Select-Object -ExpandProperty Name) -notcontains $name)) {
  Add-CATemplate -Name $name -Force
}
if ((& certutil -CATemplates 2>$null | Out-String) -notmatch [regex]::Escape($name)) {
  Restart-Service certsvc -Force
  Start-Sleep 5
}
exit 0
