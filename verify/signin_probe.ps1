# Can each sample account actually sign in right now? For verify.py (run by snapshot.yml on the DC).
# A network logon (LogonUser type 3) enforces everything the design relies on - wrong password,
# disabled, account expiry and logon-hour restrictions - unlike ValidateCredentials, which only
# checks the password. A normal logon failure is reported as accepted=false (not an error); only a
# genuine exception sets 'error'.
[CmdletBinding()]
param ([String] $samples_json, [String] $dom)
$Ansible.Changed = $false
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public static class MwSignin {
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  public static extern bool LogonUser(string user, string domain, string pass, int type, int provider, out IntPtr token);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
}
"@
# Windows PowerShell 5.1 emits a JSON array as one object; ForEach-Object { $_ } unrolls it.
$Ansible.Result = @($samples_json | ConvertFrom-Json | ForEach-Object { $_ } | ForEach-Object {
  $s = $_
  $token = [IntPtr]::Zero
  try {
    $ok = [MwSignin]::LogonUser($s.sam, $dom, $s.password, 3, 0, [ref]$token)   # LOGON32_LOGON_NETWORK
    @{ sam = $s.sam; accepted = [bool]$ok }
  } catch {
    @{ sam = $s.sam; accepted = $null; error = "$($_.Exception.Message)" }
  } finally {
    if ($token -ne [IntPtr]::Zero) { [void][MwSignin]::CloseHandle($token) }
  }
})
