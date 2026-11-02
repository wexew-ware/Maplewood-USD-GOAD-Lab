# MapleWood USD answer key (instructors only)

Generated from `scenario/district.yml` with seed 2026. Do not hand this to learners.

## Weak staff passwords

| Account | Title | Password |
| --- | --- | --- |
| `nadia.lee` | HR Specialist | `Fall2026!` |
| `sub.nathan.alvarez` | Substitute Teacher | `Welcome2026!` |
| `lucas.chavez` | Kindergarten Teacher | `Maplewood1!` |
| `kiara.baker` | Kindergarten Teacher | `Welcome2026!` |
| `emily.hamilton` | Grade 2 Teacher | `Teacher1!` |
| `malik.long` | Paraprofessional | `Teacher1!` |
| `ariana.washington` | Custodian | `Password1!` |

## Stale accounts left enabled

| Account | Description | Groups |
| --- | --- | --- |
| `2026iowens` | Graduated 2026 | - |
| `2026mross` | Graduated 2026 | - |
| `2026jcooper` | Graduated 2026 | - |
| `2026rshah` | Graduated 2026 | - |
| `2026dpark` | Graduated 2026 | - |
| `sebastian.gomez` | Left the district June 2025 | SG-MES-Teachers |
| `christopher.cooper` | Left the district June 2025 | SG-MMS-Staff |
| `dylan.cooper` | Left the district June 2025 | SG-MHS-Staff |

## Shared substitute pool

`sub01`-`sub10` all use `Substitute2026!`.

## Student password patterns

- PK, K, 1, 2: a short word + 2 digits (e.g. `tiger12`)
- Grade 3 and up: `Maple` + student ID (the EmployeeID attribute)
- PK, K: accounts have no permitted logon hours

## Phase 2 seeded weaknesses

- `\\mwsrv01\Scans` is open to Everyone (share and NTFS)
- `SG-MHS-HelpDesk` can reset passwords in every school's `Staff` OU, not just its own students
- `MW-Students-Young` (SG-GradePK, SG-GradeK, SG-Grade01, SG-Grade02): minimum length 4, complexity off, no lockout
- Students may sign in Mon/Tue/Wed/Thu/Fri 07:00-16:00 local time (UTC-8); anything outside that is an anomaly

## Phase 3 service accounts and seeded weaknesses

| Account | Password | Weakness |
| --- | --- | --- |
| `svc-sis` | `Summer2025` | Kerberoastable (SPN + weak password); crack offline |
| `svc-copier` | `Konica#Scan7` | password is in the account's Description field |
| `svc-gsync` | `Gsync-Maple-6621` | DCSync (replication rights on the domain) |
| `svc-hvac` | `Tr@neBMS-2026` | third-party vendor, never expires, allowed to RDP to the server |
| `svc-superadmin` | `Xq7!vR2mLz9#Tw5k` | honey account - any logon or Kerberos request should alert |

SYSVOL logon script `scripts\logon.bat` embeds `svc-copier`'s password in clear text.

GCDS config on srv01 (`C:\GCDS\maplewood-sync.xml`) stores `svc-gsync`'s password (base64-encoded).

## Standing local admins

| Account | Title | Password | Local admin on |
| --- | --- | --- | --- |
| `aaliyah.morgan` | Computer Science Teacher | `FalconBirch65#` | `mhs-staff01` |

Staff who are standing local admins on their own laptop: phish the password and the attacker has admin on that host, a pivot into the flat network. The workstation blocks inbound SMB, so the admin path is WinRM (5985) or RDP. Fix: remove standing local admin and manage the local Administrator password with LAPS.
