# Read-only SIS facts for verify.py (run by snapshot.yml on the SIS host): the SQL service account
# and state, the MapleGrade database and Grades table, the grade audit, and the IIS site status.
[CmdletBinding()]
param ([String] $sa_password, [String] $database)   # not 'db' - that is an alias for -Debug
$Ansible.Changed = $false
$db = $database

$svc = Get-CimInstance Win32_Service -Filter "Name='MSSQL`$SQLEXPRESS'" -ErrorAction SilentlyContinue
function Sql($query, $database) {
  $d = if ($database) { @('-d', $database) } else { @() }
  (& sqlcmd -S localhost -U sa -P $sa_password -h -1 -W -l 15 @d -Q "SET NOCOUNT ON; $query" 2>&1 | Select-Object -First 1) -as [string]
}
$dbExists = (Sql "SELECT CASE WHEN DB_ID('$db') IS NULL THEN 'no' ELSE 'yes' END").Trim()
$rows = if ($dbExists -eq 'yes') { [int]((Sql "SELECT COUNT(*) FROM dbo.Grades" $db).Trim()) } else { 0 }
$audit = if ($dbExists -eq 'yes') { [int]((Sql "SELECT COUNT(*) FROM sys.server_audits WHERE name='MapleGrade_Audit'").Trim()) } else { 0 }
$web = try { [int](Invoke-WebRequest http://localhost/ -UseBasicParsing -TimeoutSec 15).StatusCode } catch { -1 }

$Ansible.Result = @{
  sql_account = "$($svc.StartName)"; sql_state = "$($svc.State)"
  db_exists = $dbExists; grades_rows = $rows; audit = $audit; web_status = $web
}
