# 04. Helpdesk delegation overreach

**Seeded weakness.** Each school helpdesk may reset its own students, but `SG-MHS-HelpDesk` can also reset **staff** in every school.

**What the attack looks like.** A member of `SG-MHS-HelpDesk` resets a staff/admin password, then signs in as them.

## Detect

Key events (Windows Security log, shipped to Kibana by Winlogbeat):

| Event | Meaning |
| --- | --- |
| 4724 | An attempt was made to reset an account's password |
| 4738 | A user account was changed |

**Hunt.** Alert on 4724 where the **target** is outside a `Students` OU (i.e. a staff/admin account) and the **subject** is a helpdesk account. Legitimate helpdesk resets target students only.

## Respond and fix

Scope each helpdesk's reset delegation to its own `Students` OU; remove the cross-school staff delegation on `SG-MHS-HelpDesk`.

## Answer key (instructors)

Over-broad group: `SG-MHS-HelpDesk`. Members and a sample staff target are in `instructor/answer_key.md`.
