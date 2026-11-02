# 02. Grade change in the SIS

**Seeded weakness.** Weak staff passwords plus the MapleGrade SIS (`MapleGrade` on mwsrv01). A phished teacher can edit grades.

**What the attack looks like.** A teacher account signs in from an unusual host, then UPDATEs rows in `dbo.Grades`.

## Detect

Key events (Windows Security log, shipped to Kibana by Winlogbeat):

| Event | Meaning |
| --- | --- |
| 4624 | Successful logon (type 3) - watch for a teacher from an unusual host |
| 33205 | SQL Server Audit `MapleGrade_Audit` in the **Application** log (provider `MSSQL$SQLEXPRESS`) - action_id `UP`/`DL` on `dbo.Grades`, with `client_ip` |

**Hunt.** Correlate a teacher logon (e.g. `mason.green`) from a new host with event **33205** on mwsrv01 (Application channel) showing `action_id` UP/DL against `dbo.Grades`. The audit writes to the Windows Application log on mwsrv01; `client_ip` names the source.

## Respond and fix

Enforce MFA/stronger staff passwords; restrict SIS write access; review the grade audit trail; alert on grade UPDATEs outside the registrar's normal hosts.

## Answer key (instructors)

Weak staff login to try: `nadia.lee` / `Fall2026!`. Audit: `MapleGrade_Audit` -> Application log on mwsrv01.
