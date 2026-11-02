# 03. Kerberoasting the SIS service account

**Seeded weakness.** `svc-sis` runs MapleGrade and has an SPN, but a weak, crackable password.

**What the attack looks like.** Any domain user requests a service ticket for `svc-sis` and cracks it offline.

## Detect

Key events (Windows Security log, shipped to Kibana by Winlogbeat):

| Event | Meaning |
| --- | --- |
| 4769 | Kerberos service ticket requested - encryption type 0x17 (RC4) is the tell |
| 4768 | Kerberos TGT requested (the requesting user) |

**Hunt.** Hunt 4769 where **Ticket Encryption Type = 0x17** and Service Name = `svc-sis`, especially from a user workstation. One user requesting many service SPNs is roasting at scale.

## Respond and fix

Give service accounts long random passwords (or a gMSA); flag RC4 service-ticket requests; limit which accounts carry SPNs.

## Answer key (instructors)

Target: `svc-sis` (SPNs MSSQLSvc/mwsrv01.* and HTTP/maplegrade.*). Password in `instructor/answer_key.md`.
