# 05. Shared / expired substitute accounts

**Seeded weakness.** A shared substitute pool (`sub01-sub10`) with one password, and named subs that expire on 2027-06-15.

**What the attack looks like.** A shared sub account is used after hours or after the term ends; nobody can say who used it.

## Detect

Key events (Windows Security log, shipped to Kibana by Winlogbeat):

| Event | Meaning |
| --- | --- |
| 4624 | Successful logon - a `sub0x` logon outside school hours |
| 4625 | Failed logon - status 0xC0000193 means the account has expired |

**Hunt.** Flag any 4624 for `sub01-sub10` outside school hours, and 4625 with **status 0xC0000193** (expired) after 2027-06-15. Shared accounts have no individual accountability - treat every use as notable.

## Respond and fix

Replace shared subs with per-person accounts; set and enforce expiry; disable the pool out of term.

## Answer key (instructors)

Shared pool: `sub01-sub10`, password `Substitute2026!`. Named subs expire 2027-06-15.
