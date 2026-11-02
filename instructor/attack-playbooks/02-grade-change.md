# 02 — Grade change in the SIS (trigger guide)

Lesson: [`lessons/02-grade-change.md`](../../lessons/02-grade-change.md)
Target events: **4624** (teacher logon, type 3) on `mwsrv01`; **33205** SQL Server Audit in the
**Application** channel.

## What this generates

A teacher authenticating from an unusual host, and an `UPDATE` to `dbo.Grades` that the
`MapleGrade_Audit` SQL Server Audit records to the Windows Application log (shipped to ELK).

## Steps (on Kali)

```bash
# (a) teacher network logon to the SIS host -> 4624 on mwsrv01
nxc smb 192.168.56.32 -u mason.green -p 'JuniperCanyon74%'

# (b) the grade edit. The SIS app writes as svc-sis; connect as that identity and UPDATE a row.
printf 'SELECT GradeId,StudentSam,Course,Grade FROM MapleGrade.dbo.Grades WHERE GradeId=1;\nUPDATE MapleGrade.dbo.Grades SET Grade=CHAR(65),UpdatedAt=GETDATE() WHERE GradeId=1;\nUPDATE MapleGrade.dbo.Grades SET Grade=CHAR(67) WHERE GradeId=1;\nexit\n' \
  | impacket-mssqlclient 'maplewoodusd.local/svc-sis:Summer2025@192.168.56.32' -windows-auth
```

`CHAR(65)`/`CHAR(67)` = `A`/`C`; the second UPDATE restores the original grade so the SIS data is left
unchanged. Each UPDATE emits one audit event.

## Confirm in Kibana (`winlogbeat-*`)

```
winlog.channel:"Application" and winlog.event_id:33205 and winlog.computer_name:*mwsrv01*
```

and the teacher logon:

```
winlog.event_id:4624 and winlog.event_data.TargetUserName:"mason.green" and winlog.computer_name:*mwsrv01*
```

## Validation

- **4624** on `mwsrv01` for `mason.green`, `source.ip 192.168.56.99`. 
- **33205** in the **Application** channel, provider **`MSSQL$SQLEXPRESS`**, one per UPDATE.  The message
  carries `action_id:UP` (UPDATE; `DL` = delete), `succeeded:true`, `client_ip:192.168.56.99`, and   `server_principal_name:MAPLEWOOD\svc-sis`. Hunt on `action_id` `UP`/`DL` against the Grades object and
  correlate `client_ip` / a teacher 4624 with the registrar's normal hosts.
- The first lesson draft listed a generic "SQL" event; it now names **33205 / Application /
  `MSSQL$SQLEXPRESS`** concretely.
