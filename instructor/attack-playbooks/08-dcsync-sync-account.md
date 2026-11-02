# 08 — Directory-sync account abuse / DCSync (trigger guide)

Lesson: [`lessons/08-dcsync-sync-account.md`](../../lessons/08-dcsync-sync-account.md)
Target events: **4662** (replication extended right exercised) and **4624** (the preceding logon), on the DC.

## What this generates

`svc-gsync` holds replication rights (it can DCSync) and pulls password hashes from the DC as if it were a domain controller — but it is logging in from a member/attacker host.

- `svc-gsync` / `Gsync-Maple-6621`.

## Steps (on Kali)

```bash
# DCSync a single account (krbtgt) to keep it surgical; this exercises the replication right -> 4662
impacket-secretsdump 'maplewoodusd.local/svc-gsync:Gsync-Maple-6621@192.168.56.30' -just-dc-user krbtgt
```

## Confirm in Kibana (`winlogbeat-*`)

```
winlog.event_id:4662 and winlog.event_data.SubjectUserName:"svc-gsync"
```

Hunt: 4662 whose `Properties` contains a replication GUID (`1131f6aa` Get-Changes / `1131f6ad`
Get-Changes-All) where the requester is **not a domain controller**. DCs replicate constantly; a member account doing it is the tell.

## Validation

- **4662** on `mwdc01`, `SubjectUserName=svc-gsync`, `AccessMask 0x100` (control access), `Properties` containing **`{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}`** (DS-Replication-Get-Changes). 
- The lesson previously cited only `1131f6ad-…`; it now lists both `1131f6aa` and `1131f6ad` since the   surgical `-just-dc-user` pull exercises Get-Changes.
