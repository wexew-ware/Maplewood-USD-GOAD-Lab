# MapleGrade SIS database setup (run on the SIS host after MSSQL is installed).
$ErrorActionPreference = 'Stop'
$sa = 'Mssql_sa-Maple26!'
$db = 'MapleGrade'
function Sql($query, $database) {
  $d = if ($database) { @('-d', $database) } else { @() }
  & sqlcmd -S localhost -U sa -P $sa -b -l 30 @d -Q $query
  if ($LASTEXITCODE -ne 0) { throw "sqlcmd failed ($LASTEXITCODE): $query" }
}

# Wait for the SQL service to accept connections (install may have just finished).
for ($i = 0; $i -lt 30; $i++) {
  try { Sql 'SELECT 1'; break } catch { Start-Sleep 10; if ($i -eq 29) { throw } }
}

Sql "IF DB_ID('$db') IS NULL CREATE DATABASE [$db];"
Sql "IF OBJECT_ID('dbo.Grades') IS NULL CREATE TABLE dbo.Grades (GradeId INT IDENTITY PRIMARY KEY, StudentSam NVARCHAR(32) NOT NULL, Course NVARCHAR(64) NOT NULL, Term NVARCHAR(16) NOT NULL, Grade NVARCHAR(2) NOT NULL, UpdatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME());" $db
Sql "IF NOT EXISTS (SELECT 1 FROM dbo.Grades) INSERT INTO dbo.Grades (StudentSam, Course, Term, Grade) VALUES
  ('2028fpatel', 'Biology', 'Fall', 'C'),
  ('2028fpatel', 'Biology', 'Spring', 'C+'),
  ('2035mbrown', 'Art', 'Spring', 'F'),
  ('2035mbrown', 'PE', 'Fall', 'C+'),
  ('2028dpatel', 'Algebra I', 'Spring', 'B-'),
  ('2028dpatel', 'World History', 'Fall', 'B-'),
  ('2036jlee', 'Algebra I', 'Spring', 'C+'),
  ('2036jlee', 'World History', 'Spring', 'A-'),
  ('2039kpatel', 'World History', 'Spring', 'A-'),
  ('2039kpatel', 'World History', 'Spring', 'C'),
  ('2038pbrown', 'Spanish I', 'Spring', 'C'),
  ('2038pbrown', 'Spanish I', 'Spring', 'F'),
  ('2034pbrown', 'Spanish I', 'Fall', 'B'),
  ('2034pbrown', 'Art', 'Fall', 'A'),
  ('2036hjones', 'PE', 'Fall', 'C'),
  ('2036hjones', 'World History', 'Fall', 'D'),
  ('2027ksmith', 'English 9', 'Fall', 'D'),
  ('2027ksmith', 'PE', 'Spring', 'F'),
  ('2028ebrown', 'Biology', 'Spring', 'B-'),
  ('2028ebrown', 'Spanish I', 'Spring', 'C'),
  ('2028hsmith', 'World History', 'Fall', 'B-'),
  ('2028hsmith', 'Art', 'Spring', 'A'),
  ('2037hnguyen', 'Algebra I', 'Fall', 'D'),
  ('2037hnguyen', 'Art', 'Spring', 'C+');" $db

# Best-effort: audit UPDATEs to the Grades table (the grade-change detection), to the app log.
try {
  Sql "IF NOT EXISTS (SELECT 1 FROM sys.server_audits WHERE name='MapleGrade_Audit') BEGIN CREATE SERVER AUDIT MapleGrade_Audit TO APPLICATION_LOG; ALTER SERVER AUDIT MapleGrade_Audit WITH (STATE = ON); END"
  Sql "IF NOT EXISTS (SELECT 1 FROM sys.database_audit_specifications WHERE name='MapleGrade_GradesAudit') CREATE DATABASE AUDIT SPECIFICATION MapleGrade_GradesAudit FOR SERVER AUDIT MapleGrade_Audit ADD (UPDATE, DELETE ON dbo.Grades BY public) WITH (STATE = ON);" $db
} catch { Write-Warning "grade audit not configured: $_" }

Write-Host "MapleGrade database ready."
exit 0
