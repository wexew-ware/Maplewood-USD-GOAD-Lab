# Read-only: report the domain's state for verify.py (run by snapshot.yml on the DC).
#   reset_pairs_json  [{actor, target}]  whether actor's groups grant a password reset on target
#   rsop_sams_json    [sam]              which fine-grained password policy applies to each
#   gpos_json         [{name, links, registry}]  GPOs to inspect
#   repl_sams_json    [sam]              whether each account has DCSync rights on the domain head
#   sysvol_paths_json [path]             existence and SHA-256 of each SYSVOL file (e.g. the logon script)
#   adcs_template     name               ADCS: this certificate template's flags, enroll ACL and publication
[CmdletBinding()]
param ([String] $reset_pairs_json = '[]', [String] $rsop_sams_json = '[]', [String] $gpos_json = '[]',
       [String] $repl_sams_json = '[]', [String] $sysvol_paths_json = '[]', [String] $adcs_template = '')
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$Ansible.Changed = $false

function Get-CN([String] $dn) { ($dn -split '(?<!\\),', 2)[0] -replace '^CN=', '' }
# Effective advanced audit policy as a subcategory -> inclusion-setting map (/r CSV: field 2 = name, 4 = setting).
function Get-MwAuditPolicy {
  $map = @{}
  foreach ($row in (& auditpol /get /category:* /r 2>$null | Select-Object -Skip 1)) {
    $f = $row -split ','
    if ($f.Count -ge 5 -and $f[2].Trim()) { $map[$f[2].Trim()] = $f[4].Trim() }
  }
  $map
}
# Windows PowerShell 5.1 emits a JSON array as one object; ForEach-Object { $_ } unrolls it.
function Read-JsonList([String] $json) { @($json | ConvertFrom-Json | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) }

$domain = Get-ADDomain
$ous = @(Get-ADOrganizationalUnit -Filter * | ForEach-Object { $_.DistinguishedName })

$props = 'Title', 'Department', 'Office', 'Company', 'EmployeeID', 'mail', 'Manager', 'MemberOf', 'logonHours',
         'AccountExpirationDate', 'PasswordNeverExpires', 'HomeDirectory', 'HomeDrive',
         'Description', 'servicePrincipalName', 'scriptPath'
$users = @(Get-ADUser -Filter * -Properties $props | ForEach-Object {
  @{
    sam = $_.SamAccountName; dn = $_.DistinguishedName; enabled = $_.Enabled
    title = $_.Title; department = $_.Department; office = $_.Office; company = $_.Company
    employee_id = $_.EmployeeID; mail = $_.mail; manager = $_.Manager
    description = "$($_.Description)"; spns = @($_.servicePrincipalName); script_path = "$($_.scriptPath)"
    member_of = @($_.MemberOf | ForEach-Object { Get-CN $_ })
    # 42 hex digits (21 bytes, one bit per UTC hour of the week), or '' when unrestricted
    logon_hours = if ($_.logonHours) { ([BitConverter]::ToString($_.logonHours) -replace '-', '').ToLower() } else { '' }
    expires = if ($_.AccountExpirationDate) { $_.AccountExpirationDate.ToString('yyyy-MM-dd') } else { '' }
    pw_never_expires = $_.PasswordNeverExpires
    home_directory = "$($_.HomeDirectory)"; home_drive = "$($_.HomeDrive)"
  }
})

$groups = @(Get-ADGroup -Filter * -Properties MemberOf | ForEach-Object {
  @{ name = $_.Name; dn = $_.DistinguishedName; scope = "$($_.GroupScope)"; member_of = @($_.MemberOf | ForEach-Object { Get-CN $_ }) }
})
$computers = @(Get-ADComputer -Filter * | ForEach-Object { @{ name = $_.Name; dn = $_.DistinguishedName } })

$fgpps = @(Get-ADFineGrainedPasswordPolicy -Filter * | ForEach-Object {
  @{ name = $_.Name; precedence = $_.Precedence; min_length = $_.MinPasswordLength; complexity = $_.ComplexityEnabled
     history = $_.PasswordHistoryCount; lockout_threshold = $_.LockoutThreshold
     max_age_days = [int][Math]::Min($_.MaxPasswordAge.TotalDays, 99999)
     applies_to = @($_.AppliesTo | ForEach-Object { Get-CN $_ }) }
})
$rsop = @{}
foreach ($sam in (Read-JsonList $rsop_sams_json)) {
  $p = Get-ADUserResultantPasswordPolicy -Identity $sam
  $rsop[$sam] = if ($p) { $p.Name } else { '' }
}

# Effective password-reset right: an Allow ACE that applies to the object (not inherit-only) for
# one of the actor's token SIDs, granting GenericAll or the User-Force-Change-Password extended right.
$resetGuid = [guid]'00299570-246d-11d0-a768-00aa006e0529'
$adRights = [System.DirectoryServices.ActiveDirectoryRights]
$tokens = @{}
$reset = @(foreach ($pair in (Read-JsonList $reset_pairs_json)) {
  if (-not $tokens.ContainsKey($pair.actor)) {
    # tokenGroups is only returned by a base-scope search on the object itself.
    $dn = (Get-ADUser -Identity $pair.actor).DistinguishedName
    $a = Get-ADUser -SearchBase $dn -SearchScope Base -Filter * -Properties tokenGroups
    $tokens[$pair.actor] = @($a.tokenGroups) + $a.SID
  }
  $target = Get-ADUser -Identity $pair.target
  $can = $false
  foreach ($ace in (Get-Acl -Path "AD:\$($target.DistinguishedName)").Access) {
    if ($ace.AccessControlType -ne 'Allow') { continue }
    if ($ace.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
    try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) } catch { continue }
    if ($tokens[$pair.actor] -notcontains $sid) { continue }
    $r = $ace.ActiveDirectoryRights
    if ((($r -band $adRights::GenericAll) -eq $adRights::GenericAll) -or
        (($r -band $adRights::ExtendedRight) -and ($ace.ObjectType -eq $resetGuid -or $ace.ObjectType -eq [guid]::Empty))) {
      $can = $true; break
    }
  }
  @{ actor = $pair.actor; target = $pair.target; can_reset = $can }
})

# DCSync: Allow ExtendedRight ACEs on the domain head for the account's own SID, for each of the
# two replication control-access rights.
$replGuids = @{ get_changes = [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
                get_changes_all = [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' }
$domainAcl = (Get-Acl -Path "AD:\$($domain.DistinguishedName)").Access
$replication = @(foreach ($sam in (Read-JsonList $repl_sams_json)) {
  $sid = (Get-ADUser -Identity $sam).SID
  $granted = @{ get_changes = $false; get_changes_all = $false }
  foreach ($ace in $domainAcl) {
    if ($ace.AccessControlType -ne 'Allow') { continue }
    if (-not ($ace.ActiveDirectoryRights -band $adRights::ExtendedRight)) { continue }
    try { $asid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) } catch { continue }
    if ($asid -ne $sid) { continue }
    foreach ($name in @($replGuids.Keys)) {
      if ($ace.ObjectType -eq $replGuids[$name]) { $granted[$name] = $true }
    }
  }
  @{ sam = $sam; get_changes = $granted['get_changes']; get_changes_all = $granted['get_changes_all'] }
})

# SYSVOL files (e.g. the logon script): existence and SHA-256, so verify can match the exact bytes.
$sysvol = @(foreach ($path in (Read-JsonList $sysvol_paths_json)) {
  if (Test-Path -LiteralPath $path) {
    @{ path = $path; exists = $true; sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower() }
  } else { @{ path = $path; exists = $false; sha256 = '' } }
})

# ADCS: the vulnerable certificate template's flags, who may enroll, and whether a CA publishes it.
$adcs = $null
if ($adcs_template) {
  $cfg = (Get-ADRootDSE).configurationNamingContext
  $enrollSvc = @(Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$cfg" `
                   -Filter "objectClass -eq 'pKIEnrollmentService'" -Properties certificateTemplates)
  $tmplDn = "CN=$adcs_template,CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfg"
  $tmpl = Get-ADObject -Identity $tmplDn -Properties 'msPKI-Certificate-Name-Flag', 'pKIExtendedKeyUsage',
            'msPKI-Enrollment-Flag', 'msPKI-RA-Signature' -ErrorAction SilentlyContinue
  $ids = @()
  if ($tmpl) {
    $enrollGuid = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'   # Certificate-Enrollment extended right
    foreach ($ace in (Get-Acl "AD:\$tmplDn").Access) {
      if ($ace.AccessControlType -ne 'Allow') { continue }
      $r = $ace.ActiveDirectoryRights
      $enroll = ($r -band $adRights::ExtendedRight) -and ($ace.ObjectType -eq $enrollGuid -or $ace.ObjectType -eq [guid]::Empty)
      $all = ($r -band $adRights::GenericAll) -eq $adRights::GenericAll
      if ($enroll -or $all) { $ids += "$($ace.IdentityReference)" }
    }
  }
  $adcs = @{
    ca_installed = ($enrollSvc.Count -gt 0); ca = @($enrollSvc | ForEach-Object { $_.Name })
    template = $adcs_template; exists = [bool]$tmpl
    name_flag = if ($tmpl) { [int]$tmpl.'msPKI-Certificate-Name-Flag' } else { 0 }
    eku = @(if ($tmpl) { $tmpl.pKIExtendedKeyUsage })
    enrollment_flag = if ($tmpl) { [int]$tmpl.'msPKI-Enrollment-Flag' } else { -1 }
    ra_signature = if ($tmpl) { [int]$tmpl.'msPKI-RA-Signature' } else { -1 }
    enroll_identities = @($ids | Select-Object -Unique)
    published = [bool](@($enrollSvc | ForEach-Object { $_.certificateTemplates }) -contains $adcs_template)
  }
}

$gpoInfo = @(foreach ($g in (Read-JsonList $gpos_json)) {
  $gpo = Get-GPO -Name $g.name -ErrorAction SilentlyContinue
  if (-not $gpo) { @{ name = $g.name; exists = $false }; continue }
  $links = @(foreach ($t in @($g.links)) {
    $l = (Get-GPInheritance -Target $t).GpoLinks | Where-Object { $_.GpoId -eq $gpo.Id }
    @{ target = $t; linked = [bool]$l; enabled = [bool]($l -and $l.Enabled) }
  })
  $registry = @(foreach ($r in @($g.registry | Where-Object { $_ })) {
    try {
      $v = Get-GPRegistryValue -Guid $gpo.Id -Key $r.key -ValueName $r.value_name -ErrorAction Stop
      @{ key = $r.key; value_name = $r.value_name; value = "$($v.Value)"; type = "$($v.Type)" }
    } catch { @{ key = $r.key; value_name = $r.value_name; value = $null; type = $null } }
  })
  $ad = Get-ADObject -Filter "objectClass -eq 'groupPolicyContainer' -and Name -eq '{$($gpo.Id)}'" -Properties gPCFileSysPath, gPCUserExtensionNames, versionNumber
  $drivesFile = Join-Path $ad.gPCFileSysPath 'User\Preferences\Drives\Drives.xml'
  $drives = @()
  if (Test-Path -LiteralPath $drivesFile) {
    $drives = @(([xml][System.IO.File]::ReadAllText($drivesFile)).Drives.Drive | ForEach-Object {
      $fg = $_.Filters.FilterGroup
      $group = ($fg.name -split '\\')[-1]
      @{ letter = $_.Properties.letter; path = $_.Properties.path; group = $group
         sid_ok = ((Get-ADGroup -Identity $group).SID.Value -eq $fg.sid) }
    })
  }
  $ini = Join-Path $ad.gPCFileSysPath 'GPT.INI'
  $iniVersion = if (Test-Path -LiteralPath $ini) { [int]([regex]::Match([System.IO.File]::ReadAllText($ini), 'Version=(\d+)').Groups[1].Value) } else { -1 }
  @{ name = $g.name; exists = $true; links = $links; registry = $registry; drives = $drives
     version_ad = [int]$ad.versionNumber; version_ini = $iniVersion; user_extensions = "$($ad.gPCUserExtensionNames)" }
})

$Ansible.Result = @{
  dns_root = $domain.DNSRoot; netbios = $domain.NetBIOSName; utc_now = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
  ous = $ous; users = $users; groups = $groups; computers = $computers
  fgpps = $fgpps; resultant_policies = $rsop; reset_rights = $reset; gpos = $gpoInfo
  replication_grants = $replication; sysvol_files = $sysvol; adcs = $adcs; audit_policy = (Get-MwAuditPolicy)
  csv_left_on_dc = (Test-Path 'C:\Windows\Temp\mw_users.csv')
}
