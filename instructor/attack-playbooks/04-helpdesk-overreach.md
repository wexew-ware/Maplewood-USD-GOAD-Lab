# 04 — Helpdesk delegation overreach (trigger guide)

Lesson: [`lessons/04-helpdesk-overreach.md`](../../lessons/04-helpdesk-overreach.md)
Target events: **4724** (password reset attempt) and **4738** (user account changed), on the DC.

## What this generates

A member of the over-broad `SG-MHS-HelpDesk` group resets a **staff** account's password (helpdesk should only reset its own students). Subject = helpdesk account, target = staff.

- Helpdesk member: `sam.nguyen` / `Willow-Canyon-3302` (in `SG-MHS-HelpDesk`).
- Staff target: `mason.green` (MES teacher).

## Steps (on Kali)

```bash
net rpc password "mason.green" "JuniperCanyon74%" \
  -U "sam.nguyen%Willow-Canyon-3302" -W "maplewoodusd.local" -S "192.168.56.30"
```

Resetting to `mason.green`'s existing answer-key password (`JuniperCanyon74%`) fires the events while leaving the account's password unchanged. (The cross-school staff reset succeeds, which is the point.)

## Confirm in Kibana (`winlogbeat-*`)

```
winlog.event_id:(4724 or 4738) and winlog.event_data.TargetUserName:"mason.green" and winlog.event_data.SubjectUserName:"sam.nguyen"
```

Hunt: 4724 where the **target** DN is outside a `Students` OU and the **subject** is a helpdesk account.

## Validation
- **4724** and **4738**, `TargetUserName=mason.green`, `SubjectUserName=sam.nguyen`, on `mwdc01`. 
- Lesson matches reality — no change needed.
