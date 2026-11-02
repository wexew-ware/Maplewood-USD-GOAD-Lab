# 10. Honey account touched

**Seeded weakness.** `svc-superadmin` looks like a privileged superintendent admin but grants nothing - a tripwire.

**What the attack looks like.** An attacker enumerating or spraying the domain tries to use `svc-superadmin`.

## Detect

Key events (Windows Security log, shipped to Kibana by Winlogbeat):

| Event | Meaning |
| --- | --- |
| 4771 | Kerberos pre-auth failed for the decoy - a guess/spray against it (status 0x18) |
| 4625 / 4776 | Failed NTLM logon and DC credential-validation failure for the decoy |
| 4769 | A service ticket requested for the decoy's SPN (roasting) - highest-signal |
| 4768 / 4624 | TGT or logon success - only if someone holds the decoy's password (rare, highest severity) |

**Hunt.** Alert on **any** 4624/4625/4768/4769/4771/4776 referencing `svc-superadmin`. No legitimate process uses it, so every hit is high-signal. This is the cheapest, highest-fidelity detection in the lab.

## Respond and fix

Keep the decoy enabled but unused; wire its events straight to a high-priority alert; never log in as it.

## Answer key (instructors)

Honey account: `svc-superadmin` (do not use; any auth = alert).
