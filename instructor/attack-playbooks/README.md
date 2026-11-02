# Attack playbooks — trigger the lesson telemetry from Kali

**Instructors only.** One playbook per lesson in [`lessons/`](../../lessons/): the exact steps to run
from the **Kali attacker box** (`192.168.56.99`, see [`attacker/`](../../attacker/)) to generate the
Windows events the blue team is meant to detect, plus how to confirm each one landed in ELK.

These use real lab credentials (seed **2026**, see [`answer_key.md`](../answer_key.md)); not intended to be shown to blue-team learners during exercises.

## Every event here was validated against this lab on 2026-10-25

Each playbook ends with a **Validated** block recording what actually shipped to Elasticsearch, and the
lessons were corrected where reality differed from the first draft. Notable corrections:

- **01** — an NTLM spray lands as **4625** (sub-status `0xC000006A`) *and* **4776** on the DC; **4771**
  only appears for a *Kerberos* spray during permitted hours. Outside student logon hours (evenings,
  weekends) a Kerberos attempt is **4768 with failure code `0x12`** (logon-hours/revoked), not 4771.
- **02** — the SQL Server Audit event is **33205** in the **Application** channel (provider
  `MSSQL$SQLEXPRESS`), not a generic "SQL" event.
- **06 / 09** — **4663 does not fire**: SYSVOL and the `Scans` share have no SACL. **5145** (Detailed
  File Share) is the reliable signal and needs no SACL.
- **10** — an attacker *without* the decoy's password produces **4625 / 4776 / 4771 / 4769**; 4768/4624
  only appear if someone actually holds the password (rare, highest severity).

## Setup (once)

```bash
cd attacker && vagrant up && vagrant ssh      # DNS to the DC is already wired (see attacker/README.md)
# tooling (netexec ships in the box; the rest via apt):
sudo apt install -y smbclient impacket-scripts krb5-user
```

Kerberos tools resolve the realm via the DC (SRV records) — no extra config needed.

## Confirm in Kibana

Open `http://192.168.56.50:5601` → Discover, index pattern `winlogbeat-*`, time picker around your run. Each playbook gives the exact KQL. A quick way to see everything one attack produced:

```
(source.ip:"192.168.56.99" or winlog.event_data.IpAddress:"192.168.56.99") and winlog.event_id:(4624 or 4625 or 4768 or 4769 or 4771 or 4776 or 4662 or 4724 or 4738 or 5145)
```

| #   | Playbook                                                | Primary events                 |
| --- | ------------------------------------------------------- | ------------------------------ |
| 01  | [student password spray](01-student-password-spray.md)  | 4625 + 4776 (4771 on Kerberos) |
| 02  | [grade change in the SIS](02-grade-change.md)           | 4624 + 33205                   |
| 03  | [kerberoast the SIS account](03-kerberoast-sis.md)      | 4769 (0x17) + 4768             |
| 04  | [helpdesk overreach](04-helpdesk-overreach.md)          | 4724 + 4738                    |
| 05  | [shared / expired substitutes](05-shared-substitute.md) | 4624 (+ 4625 0xC0000193)       |
| 06  | [SYSVOL credentials](06-sysvol-credentials.md)          | 5145                           |
| 07  | [stale account reuse](07-stale-account-reuse.md)        | 4624 + 4768                    |
| 08  | [DCSync](08-dcsync-sync-account.md)                     | 4662                           |
| 09  | [share ransomware](09-share-ransomware.md)              | 5145 (burst)                   |
| 10  | [honey account](10-honey-account.md)                    | 4769 / 4771 / 4625             |
 