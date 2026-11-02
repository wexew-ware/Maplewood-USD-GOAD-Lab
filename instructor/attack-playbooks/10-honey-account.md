# 10 — Honey account touched (trigger guide)

Lesson: [`lessons/10-honey-account.md`](../../lessons/10-honey-account.md)
Target events: **any** event referencing `svc-superadmin` — validated: **4769 / 4771 / 4625 / 4776**.

## What this generates

An attacker enumerating/spraying the domain tries to use the decoy `svc-superadmin`. Nothing legitimate ever touches it, so every hit is high-signal.

## Steps (on Kali)

```bash
# NTLM guess -> 4625 (+4776);  Kerberos guess -> 4771
nxc smb 192.168.56.30 -u svc-superadmin -p 'WrongHoneyPw1'
impacket-getTGT 'maplewoodusd.local/svc-superadmin:WrongHoneyPw1' -dc-ip 192.168.56.30
# the decoy also has an SPN, so a kerberoast of the domain requests its ticket -> 4769 (see playbook 03)
nxc ldap 192.168.56.30 -u nadia.lee -p 'Fall2026!' --kerberoasting /tmp/roast.txt
```

## Confirm in Kibana (`winlogbeat-*`)

```
(winlog.event_data.TargetUserName:"svc-superadmin" or winlog.event_data.ServiceName:"svc-superadmin")
```

Hunt: alert on **any** 4624/4625/4768/4769/4771/4776 referencing `svc-superadmin` — the cheapest, highest-fidelity detection in the lab.

## Validation

- **4769** `ServiceName=svc-superadmin`, `enc 0x17` — the decoy's SPN roasted (requested by `nadia.lee`). 
- **4771** `TargetUserName=svc-superadmin`, `Status 0x18` — Kerberos pre-auth guess. 
- **4625 + 4776** `svc-superadmin`, `0xC000006A` — NTLM logon + DC credential-validation failure. 
- **4768 / 4624** are **not** produced because they require someone to actually hold the decoy's password. 
