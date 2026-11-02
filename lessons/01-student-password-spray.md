# 01. Student password spray

**Seeded weakness.** Young students (grades PK, K, 1, 2) get short, guessable passwords (a word + 2 digits) and the young-student policy has no lockout.

**What the attack looks like.** One or two common passwords are tried against many student accounts from a single host in a short window.

## Detect

Key events (Windows Security log, shipped to Kibana by Winlogbeat):

| Event | Meaning |
| --- | --- |
| 4625 | Failed logon, type 3 (sub-status 0xC000006A = bad password) - one per sprayed account |
| 4776 | The DC validated and rejected the NTLM credentials - one per attempt (the key NTLM signal on a DC) |
| 4771 / 4768 | Kerberos spray: 4771 code 0x18 (bad password) during permitted hours; outside student logon hours you get 4768 failures code 0x12 (logon-hours/revoked) instead |

**Hunt.** Group 4625/4776 (and 4771 for a Kerberos spray) by source host over 5-minute windows; a spray is one source failing against **many distinct** student accounts across the young-grade groups. Compare the distinct-target count to a normal user's typo rate.

## Respond and fix

Raise the student password policy (length, and a lockout threshold for the young-student FGPP); reset predictable passwords; alert on N+ distinct failed targets from one source.

## Answer key (instructors)

Sample target: `2038jmartinez` (Grade 1). Pattern: a word from the kid-word list + 2 digits (see `instructor/answer_key.md`).
