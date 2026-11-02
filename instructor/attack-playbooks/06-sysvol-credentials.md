# 06 — Credentials in a SYSVOL logon script (trigger guide)

Lesson: [`lessons/06-sysvol-credentials.md`](../../lessons/06-sysvol-credentials.md)
Target event: **5145** (Detailed File Share) on the DC for the read of `NETLOGON\logon.bat`.

## What this generates

An attacker reads the staff logon script from NETLOGON and harvests the hard-coded `svc-copier` password. Every staff logon reads this file, so the signal is *who else* reads it.

## Steps (on Kali)

```bash
smbclient //192.168.56.30/NETLOGON -U 'maplewoodusd.local\nadia.lee%Fall2026!' \
  -c 'ls; get logon.bat /tmp/logon.bat'
grep -i pass /tmp/logon.bat     # the svc-copier password in clear text
```

## Confirm in Kibana (`winlogbeat-*`)

```
winlog.event_id:5145 and winlog.event_data.RelativeTargetName:*logon.bat* and winlog.event_data.IpAddress:"192.168.56.99"
```

Hunt: 5145 for `logon.bat` from **unexpected hosts** or accounts that never log on interactively.
Baseline the normal readers (every staff logon) first.

## Validation

- **5145** on `mwdc01`, `SubjectUserName=nadia.lee`, `ShareName=\\*\NETLOGON`,
  `RelativeTargetName=logon.bat`, `winlog.event_data.IpAddress 192.168.56.99` (5145 has **no** `source.ip` field — hunt `event_data.IpAddress`). 
- **4663 did NOT fire.** 4663 (object access) needs a **SACL** on the file, and SYSVOL files have none
  by default. 5145 (Detailed File Share) needs no SACL and is the reliable signal — the lesson now says so (4663 only if you add a SACL).
