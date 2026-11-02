# 07. Stale account reuse

**Seeded weakness.** Some graduated students and former staff were left enabled in the `Disabled` OUs.

**What the attack looks like.** A long-untouched account (a graduate or ex-employee) suddenly authenticates.

## Detect

Key events (Windows Security log, shipped to Kibana by Winlogbeat):

| Event | Meaning |
| --- | --- |
| 4624 | Successful logon for an account under OU=Disabled |
| 4768 | Kerberos TGT requested for such an account |

**Hunt.** Alert on any 4624/4768 for accounts whose DN is under `OU=Graduated` or `OU=Former Staff`. These should never log on - any authentication is suspicious.

## Respond and fix

Disable (don't just move) departed accounts; review enabled accounts in the Disabled OUs; alert on any use.

## Answer key (instructors)

Sample enabled stale account: `2026iowens` (in `Graduated`).
