# 09. Share ransomware drill

**Seeded weakness.** Class shares hold student work, and the `Scans` share is open to Everyone - a ransomware blast radius.

**What the attack looks like.** One account mass-renames/encrypts files across a class share or the open `Scans` share.

## Detect

Key events (Windows Security log, shipped to Kibana by Winlogbeat):

| Event | Meaning |
| --- | --- |
| 5145 | Detailed File Share: a burst of per-file writes/renames/deletes (reliable - needs no SACL; the client IP is in `event_data.IpAddress`, not `source.ip`) |
| 4663 | Object access on the files - only with a SACL on the share (none by default); otherwise rely on 5145 |

**Hunt.** Watch for a spike in 5145/4663 **write and delete** events from a single account (or `winlog.event_data.IpAddress`) over a short window on mwsrv01 shares. A user touching hundreds of files a minute is not normal.

## Respond and fix

Lock down the open `Scans` share; least-privilege share/NTFS; backups + canary files; rate-based alerts.

## Answer key (instructors)

Open share: `\\mwsrv01\Scans` (Everyone). Class shares per grade.
