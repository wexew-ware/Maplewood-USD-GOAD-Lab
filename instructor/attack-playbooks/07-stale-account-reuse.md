# 07 — Stale account reuse (trigger guide)

Lesson: [`lessons/07-stale-account-reuse.md`](../../lessons/07-stale-account-reuse.md)
Target events: **4624** (logon for an account under an `OU=Disabled` tree) and **4768** (its Kerberos TGT).

## What this generates

A graduated student / former-staff account that was left enabled suddenly authenticates — these DNs
should never log on.

- Graduate (enabled): `2026iowens` / `Maple105809` (OU=Graduated).
- Former staff (enabled): `sebastian.gomez` / `OrchardQuarry14*` (OU=Former Staff).

## Steps (on Kali)

```bash
# NTLM logon -> 4624 (+4776)
nxc smb 192.168.56.30 -u 2026iowens -p 'Maple105809'
# Kerberos TGT -> 4768
impacket-getTGT 'maplewoodusd.local/2026iowens:Maple105809' -dc-ip 192.168.56.30
nxc smb 192.168.56.30 -u sebastian.gomez -p 'OrchardQuarry14*'
```

## Confirm in Kibana (`winlogbeat-*`)

```
winlog.event_id:(4624 or 4768 or 4776) and winlog.event_data.TargetUserName:(2026iowens or sebastian.gomez)
```

Hunt: alert on **any** 4624/4768 whose account DN is under `OU=Graduated` or `OU=Former Staff`.

## Validation

- **4624** for `2026iowens` and `sebastian.gomez`, `source.ip 192.168.56.99`. 
- **4768** for `2026iowens` (TGT issued, `Status 0x0`). 
- **4776** also logged (NTLM validation success); a useful corroborator
