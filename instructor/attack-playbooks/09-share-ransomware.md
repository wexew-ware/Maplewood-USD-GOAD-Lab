# 09 — Share ransomware drill (trigger guide)

Lesson: [`lessons/09-share-ransomware.md`](../../lessons/09-share-ransomware.md)
Target event: **5145** (Detailed File Share) burst on `mwsrv01` — a spike of writes/deletes from one account.

## What this generates

One account touches hundreds of files a minute across a share — the mass-encrypt/rename shape. The `Scans` share is open to Everyone, so any domain user can do it.

## Steps (on Kali)

```bash
mkdir -p /tmp/rw && for i in $(seq 1 25); do echo locked > /tmp/rw/file$i.txt; done
# write burst
smbclient //192.168.56.32/Scans -U 'maplewoodusd.local\nadia.lee%Fall2026!' -c 'prompt OFF; lcd /tmp/rw; mput *'
# delete burst
smbclient //192.168.56.32/Scans -U 'maplewoodusd.local\nadia.lee%Fall2026!' -c 'prompt OFF; del file*'
```

Scale up the loop (hundreds of files) for a sharper spike. Cleans up after itself (the files are deleted).

## Confirm in Kibana (`winlogbeat-*`)

```
winlog.event_id:5145 and winlog.event_data.ShareName:*Scans* and winlog.event_data.IpAddress:"192.168.56.99"
```

Hunt: a rate spike of 5145 (writes + deletes) from a single `event_data.IpAddress` / account over a short window on `mwsrv01` shares.

## Validated (2026-10-25)

- **5145 ×79** on `mwsrv01`, `SubjectUserName=nadia.lee`, `ShareName=\\*\Scans`, per-file
  `RelativeTargetName`, `winlog.event_data.IpAddress 192.168.56.99` (5145 has **no** `source.ip` — hunt `event_data.IpAddress`).  A clear, obvious burst.
- **4663 does NOT fire** unless you add a SACL to the share.
