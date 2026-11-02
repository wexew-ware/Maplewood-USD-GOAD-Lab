# 01 — Student password spray (trigger guide)

Lesson: [`lessons/01-student-password-spray.md`](../../lessons/01-student-password-spray.md)
Target events: **4625** (+ **4776**) on the DC; **4771** for a Kerberos spray.

## What this generates

One source (`192.168.56.99`) failing to log on against **many distinct** student accounts in a short
window — the spray shape the blue team groups by source.

## Steps (on Kali)

Build a target list of young-grade students (Grade 1/2) and spray one wrong password over NTLM:

```bash
# any 50 student sams work; e.g. pull grade 1/2 sams you have, one per line, into young.txt
nxc smb 192.168.56.30 -u young.txt -p 'Spray2026!' --continue-on-success
```

Optional Kerberos variant (produces 4771 **only during permitted student hours**, Mon–Fri 07:00–16:00 Pacific):

```bash
for s in $(head -5 young.txt); do impacket-getTGT "maplewoodusd.local/$s:WrongPass1" -dc-ip 192.168.56.30; done
```

## Confirm in Kibana (`winlogbeat-*`)

```
winlog.event_id:(4625 or 4776) and source.ip:"192.168.56.99" and winlog.event_data.TargetUserName:(2037* or 2038*)
```

Spray detection: `count(distinct TargetUserName)` from one `source.ip` over 5 minutes ≫ a human's typo rate.

## Validation

- **4625 ×50** — `winlog.event_data.SubStatus = 0xC000006A` (bad password), logon type 3, `source.ip 192.168.56.99`. 
- **4776 ×50** — the DC's NTLM credential-validation failures, `Status 0xC000006A`, one per attempt.  (This is the key NTLM signal *on a domain controller* )
- **4771:** not produced by the NTLM spray. The Kerberos variant run **outside** student logon hours
  (this run was a Sunday) returned `KDC_ERR_CLIENT_REVOKED` and logged **4768 with failure code `0x12`**  (logon-hours/revoked) — *not* 4771. During permitted hours a bad-password Kerberos AS-REQ yields   **4771 with code `0x18`**. The lesson now states both.
