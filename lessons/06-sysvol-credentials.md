# 06. Credentials in a SYSVOL logon script

**Seeded weakness.** The staff logon script (`\\maplewoodusd.local\NETLOGON\logon.bat`) maps a share using `svc-copier`'s password in clear text.

**What the attack looks like.** An attacker reads the logon script from NETLOGON and harvests the hardcoded `svc-copier` password.

## Detect

Key events (Windows Security log, shipped to Kibana by Winlogbeat):

| Event | Meaning |
| --- | --- |
| 5145 | Detailed File Share: the read of NETLOGON\logon.bat (reliable - needs no SACL; the client IP is in `event_data.IpAddress`, not `source.ip`) |
| 4663 | Object access on the file - only if a SACL is set (SYSVOL has none by default); otherwise rely on 5145 |

**Hunt.** Baseline who reads the logon script (every staff logon does). Hunt 5145 for `logon.bat` from **unexpected hosts** (filter on `winlog.event_data.IpAddress`) or accounts that never log on interactively.

## Respond and fix

Remove credentials from SYSVOL; rotate `svc-copier`'s password; map shares by GPP with no stored creds.

## Answer key (instructors)

Script embeds `svc-copier`'s password (see `instructor/answer_key.md`).
