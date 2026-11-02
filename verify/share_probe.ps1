# Try share reads and writes as other accounts for verify.py (run by snapshot.yml on a workstation).
# Each probe runs in its own LOGON32_LOGON_NEW_CREDENTIALS session (logon type 9): the local
# identity is unchanged and network access uses the probe account, so the file server sees a real
# network logon (logon hours apply) and probes never share an SMB session. A successful write
# creates a file opened with DeleteOnClose, so nothing is left behind.
[CmdletBinding()]
param ([String] $probes_json, [String] $domain)
$Ansible.Changed = $false
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class MwLogon {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUser(string user, string domain, string password, int logonType, int provider, out IntPtr token);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);
}
"@

# Windows PowerShell 5.1 emits a JSON array as one object; ForEach-Object { $_ } unrolls it.
$Ansible.Result = @($probes_json | ConvertFrom-Json | ForEach-Object { $_ } | ForEach-Object {
  $p = $_
  $token = [IntPtr]::Zero
  $result = @{ sam = $p.sam; unc = $p.unc; op = $p.op; allowed = $false; error = '' }
  try {
    if (-not [MwLogon]::LogonUser($p.sam, $domain, $p.password, 9, 3, [ref]$token)) {
      throw (New-Object ComponentModel.Win32Exception([Runtime.InteropServices.Marshal]::GetLastWin32Error()))
    }
    $ctx = [Security.Principal.WindowsIdentity]::Impersonate($token)
    try {
      if ($p.op -eq 'read') {
        [void][IO.Directory]::GetFileSystemEntries($p.unc)
      } else {
        $f = [IO.File]::Create((Join-Path $p.unc "mw-verify-$([guid]::NewGuid()).tmp"), 1, [IO.FileOptions]::DeleteOnClose)
        $f.Dispose()
      }
      $result.allowed = $true
    } finally { $ctx.Undo() }
  } catch {
    $result.error = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
    $result.error = "$($result.error)".Trim()
  } finally {
    if ($token -ne [IntPtr]::Zero) { [void][MwLogon]::CloseHandle($token) }
  }
  $result
})
