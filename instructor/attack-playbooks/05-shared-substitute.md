# 05 — Shared / expired substitute accounts (trigger guide)

Lesson: [`lessons/05-shared-substitute.md`](../../lessons/05-shared-substitute.md)
Target events: **4624** (a shared `sub0x` logon, note the time) and **4625** with status **0xC0000193**
(account expired).

## What this generates

Use of a shared substitute account (no individual accountability), and — once an account is past its
expiry — a failed logon that specifically signals expiry.

- Shared pool: `sub01`–`sub10`, all `Substitute2026!`.

## Steps (on Kali)

```bash
# shared-account use -> 4624 (type 3) on the DC
nxc smb 192.168.56.30 -u sub01 -p 'Substitute2026!'
```

### Reproducing the 0xC0000193 (expired) event

The named substitutes expire **2027-06-15**, so before that date no account is expired and 0xC0000193 cannot occur naturally. To demonstrate it on demand, temporarily expire a throwaway test account (as a domain admin), attempt a logon, then clear the expiry:

```powershell
# on the DC (instructor): set a past expiry, then after the test clear it
Set-ADUser sub10 -AccountExpirationDate (Get-Date).AddDays(-1)
# ... from Kali: nxc smb 192.168.56.30 -u sub10 -p 'Substitute2026!'   (-> 4625 status 0xC0000193)
Clear-ADAccountExpiration sub10
```

## Confirm in Kibana (`winlogbeat-*`)

```
winlog.event_id:4624 and winlog.event_data.TargetUserName:"sub01"
winlog.event_id:4625 and winlog.event_data.TargetUserName:sub* and winlog.event_data.Status:"0xc0000193"
```

Hunt: any `sub0x` 4624 outside school hours, and 4625 `0xC0000193` after term end — shared accounts have no individual accountability, so treat every use as notable.

## Validation

- **4624** for `sub01`, logon type 3, `source.ip 192.168.56.99`. ✅ (Substitutes have no logon-hours   restriction, so the logon succeeds at any time; the signal is *who/when*, not a block.)
- **4625 / 0xC0000193:** not triggerable today — no account is expired yet (named subs expire
  2027-06-15). The event ID/status in the lesson is correct for an expired account; reproduce it with   the throwaway-expiry step above. Lesson unchanged.
