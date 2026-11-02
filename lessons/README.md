# MapleWood USD - blue-team lessons

One lesson per seeded weakness: run the attack, find it in the logs, fix it. All events ship to Kibana via Winlogbeat (Phase 4 ELK). Account names below are for this lab's seed; see `instructor/answer_key.md` for passwords.

| # | Lesson | Primary events |
| --- | --- | --- |
| 01 | [Student password spray](01-student-password-spray.md) | 4625 / 4776 (4771 Kerberos) |
| 02 | [Grade change in the SIS](02-grade-change.md) | 4624 + 33205 (SQL audit) |
| 03 | [Kerberoasting the SIS service account](03-kerberoast-sis.md) | 4769 (RC4 0x17) |
| 04 | [Helpdesk delegation overreach](04-helpdesk-overreach.md) | 4724 |
| 05 | [Shared / expired substitute accounts](05-shared-substitute.md) | 4624 / 4625 (0xC0000193) |
| 06 | [Credentials in a SYSVOL logon script](06-sysvol-credentials.md) | 5145 |
| 07 | [Stale account reuse](07-stale-account-reuse.md) | 4624 / 4768 |
| 08 | [Directory-sync account abuse (DCSync)](08-dcsync-sync-account.md) | 4662 |
| 09 | [Share ransomware drill](09-share-ransomware.md) | 5145 |
| 10 | [Honey account touched](10-honey-account.md) | 4769 / 4771 / 4625 |
