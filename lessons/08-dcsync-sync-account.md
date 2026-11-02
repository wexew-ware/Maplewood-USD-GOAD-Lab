# 08. Directory-sync account abuse (DCSync)

**Seeded weakness.** `svc-gsync` (a directory-sync account) was granted replication rights on the domain - it can DCSync.

**What the attack looks like.** `svc-gsync` (or anyone who compromises it) replicates password hashes from the DC.

## Detect

Key events (Windows Security log, shipped to Kibana by Winlogbeat):

| Event | Meaning |
| --- | --- |
| 4662 | An operation was performed on an object - replication extended rights (DS-Replication-Get-Changes `1131f6aa` / -Get-Changes-All `1131f6ad`) |
| 4624 | The logon that preceded the replication request |

**Hunt.** Hunt 4662 referencing the replication GUIDs (`1131f6aa`/`1131f6ad`) where the requester is **not a domain controller** - e.g. `svc-gsync` from a member host. DCs replicate constantly; non-DCs should not.

## Respond and fix

Remove replication rights from `svc-gsync`; use a least-privilege sync method; alert on non-DC 4662 replication.

## Answer key (instructors)

Account with DCSync: `svc-gsync` (Get-Changes + Get-Changes-All on the domain head).
