# MapleWood USD — a K-12 district lab for GOAD

MapleWood USD turns [Game of Active Directory (GOAD)](https://github.com/Orange-Cyberdefense/GOAD) into something K-12 security staff recognize: a small school district with a District Office, three schools, Pre-K through Grade 12 students, teachers, substitutes and facilities staff. It is built for **blue teamers** and comes with realistic district weaknesses, each with a clear detection story.

> **Lab only.** Like GOAD, this environment is deliberately weak. Never reuse it for production and never expose it to the internet. All names are synthetic; never load real student or staff data.

## What you get (Phases 0–4)

- Domain `maplewoodusd.local` (NetBIOS `MAPLEWOOD`)
- School-based OU tree: District Office (Administration, Technology, Facilities, Substitutes, Servers) and Maplewood Elementary, Middle and High, each with Staff (Teachers, Support Staff), Students (one OU per grade, Pre-K–12) and Computers
- 350 students (25 per grade), 28 teachers (2 per grade), principals, support staff, district staff, 8 named substitutes with expiring accounts and a shared `sub01`–`sub10` pool
- Role, school and grade security groups, nested the way districts nest them
- Pre-K and Kindergarten accounts that exist but cannot sign in
- Seeded weaknesses: guessable staff passwords, predictable student passwords, a shared substitute password, graduates and former staff left enabled
- A file server, `mwsrv01`, with:
  - staff home folders, mapped as H:
  - district, department and school staff shares
  - one class share per grade: teachers write, students read
  - permissions granted through `DL-Share-*` domain-local groups (AGDLP)
- Fine-grained password policies for admins, staff, students and young students
- Students in Grades 1–12 can sign in only during school hours (Mon–Fri 07:00–16:00 Pacific)
- Per-school helpdesk groups that can reset passwords for their own school's students
- GPOs: student lockdown on the Students OUs, and drive maps targeted by security group
- Phase 2 seeded weaknesses:
  - an open `Scans` share
  - one helpdesk group (MHS) that can also reset staff passwords in every school
  - a weak policy with no lockout for Pre-K to Grade 2
- Service accounts in `OU=Service Accounts` (created by GOAD from `config.json`):
  - `svc-sis` — Kerberoastable: an SPN on an account with a weak, crackable password
  - `svc-copier` — its password written into the account Description
  - `svc-gsync` — a directory-sync account over-privileged with DCSync rights on the domain
  - `svc-hvac` — a vendor account that never expires and may RDP to the server
- `svc-superadmin` — a honey account: looks like a superintendent admin but grants nothing; any logon or Kerberos request for it should alert
- A SYSVOL logon script (`scriptPath` on staff) that maps a share using `svc-copier`'s password in clear text
- A standing local admin: an MHS teacher is in the local `Administrators` group on their own staff laptop (WS01), so a phished password becomes a foothold to pivot from
- The **MapleGrade SIS** on `mwsrv01`: MSSQL Express + IIS, running as `svc-sis`, with a `MapleGrade` database and a `Grades` table (the grade-change target, audited) and a staff sign-in web page
- **ADCS** on the DC with a deliberately vulnerable **ESC1** template, `MapleWood-WiFi-User`: any domain user can enroll and supply their own subject with a client-authentication EKU (impersonation — the staff-Wi-Fi certificate story)
- An **audit-policy GPO** (`MW Audit Policy`) that turns on the advanced-audit subcategories the detections rely on (Kerberos service tickets for 4769, directory-service access for 4662, detailed file share for 5145, logon, account management, …) on every domain computer
- A **blue-team lesson pack** in [`lessons/`](lessons/): one lesson per seeded weakness — run the attack, find it in the logs, fix it — with the real account names for this seed and the Windows event IDs to hunt
- An **ELK stack** from GOAD's `elk` extension: Elasticsearch/Logstash/Kibana on a Linux box at .50, with **Winlogbeat** and **Sysmon** on every domain host, so the Security, Sysmon and PowerShell events the lessons rely on ship into Kibana for hunting
- Five VMs on VirtualBox:
  - `MAPLEWOOD-DC01` (mwdc01, .30)
  - `MAPLEWOOD-WS01` (mhs-staff01, .31)
  - `MAPLEWOOD-SRV01` (mwsrv01, .32)
  - `MAPLEWOOD-WS02` (mms-lab01, .33), a student lab PC
  - `ELK` (.50), Elasticsearch/Logstash/Kibana — Kibana at `http://192.168.56.50:5601`
- An optional standalone **Kali attacker box** (.99) for running the lesson attacks — see [`attacker/`](attacker/). It's a separate Vagrant project on the same host-only network, deliberately outside GOAD so `goad reset` never wipes your tooling.

## Build phases

The lab was built in five phases, each ending in a usable lab. This README and `verify.py --phase N` refer to them:

| Phase | Adds |
| --- | --- |
| 0 Skeleton | DC01 and WS01, the `maplewoodusd.local` domain, `install.sh` |
| 1 Directory | The OU tree, groups, story accounts, students, staff, substitutes and stale accounts |
| 2 Resources | SRV01 and WS02, shares, home folders, password policies, logon hours, helpdesk delegation and GPOs |
| 3 Seeded weaknesses | Service accounts, the SYSVOL logon script, the ADCS ESC1 template, the MapleGrade SIS and the honey account |
| 4 Detection | The audit-policy GPO, the lesson pack, and ELK with Winlogbeat and Sysmon |

You don't build them one at a time: the install below builds all of it in one run, apart from ELK, which is a separate extension install.

## Quick start

Requirements:

- A Linux host with VirtualBox, Vagrant and GOAD's other prerequisites (see the [GOAD docs](https://orange-cyberdefense.github.io/GOAD/))
- GOAD at commit `992307a`, the version this lab is built and tested against; newer GOAD commits are untested
- Python 3.11–3.13 for GOAD's Ansible (see the note below if your `python3` is newer)
- RAM: about 18 GB free for the four Windows VMs, 22 GB with ELK, and 25 GB with the Kali attacker box as well
- Disk: about 110 GB for the lab VMs and their base boxes, about 30 GB more for the Kali box, and room for snapshots (the four phase snapshots on the reference build took about 90 GB)

> **NOTE**: GOAD's `mssql` role hard-codes a SQL 2019 Express installer link that now 404s. The generated inventory overrides it (`download_url_2019`) with the stable `go.microsoft.com/fwlink/?linkid=866658`; if Microsoft retires that too, update it in `scenario`/the generator.

> **NOTE**: GOAD `992307a` pins ansible-core 2.18, which runs on Python 3.11–3.13 only. The first time `goad.sh` runs it builds its virtualenv, `~/.goad/.venv`, with your `python3`; if that folder already exists it skips setup entirely. If your `python3` is newer than 3.13, build the virtualenv yourself before the first `./goad.sh`, for example with [uv](https://docs.astral.sh/uv/), from the directory you cloned GOAD into:
>
> ```bash
> uv venv --python 3.12 --seed ~/.goad/.venv
> source ~/.goad/.venv/bin/activate
> pip install -r GOAD/requirements_311.yml
> (cd GOAD/ansible && ansible-galaxy install -r requirements_311.yml)
> deactivate
> ```

```bash
git clone https://github.com/Orange-Cyberdefense/GOAD.git
git -C GOAD checkout 992307a                 # the GOAD version this lab is tested against
git clone https://github.com/<you>/maplewood-goad.git
cd maplewood-goad
./install.sh ../GOAD
cd ../GOAD
./goad.sh -t install -l MAPLEWOOD -p virtualbox
```

`install.sh` copies the lab into `GOAD/ad/MAPLEWOOD`, the MapleWood playbooks and roles into `GOAD/ansible/`, and adds a `MAPLEWOOD:` entry to `GOAD/playbooks.yml`. Run it again after pulling updates; `./install.sh --uninstall ../GOAD` removes everything it added.

The ELK stack is GOAD's stock `elk` extension, installed after the core build (it needs Ansible's `sshpass`, as the ELK box uses password SSH):

```bash
sudo apt-get install -y sshpass
./goad.sh                                    # then, in the shell:
#   load <instance id>                       # e.g. 4abff6-maplewood-virtualbox
#   install_extension elk                    # builds the ELK VM, installs the stack and the agents
```

## Changing the district

Everything comes from one file, [`scenario/district.yml`](scenario/district.yml). It covers schools and grades, counts per role, story accounts, password patterns, stale accounts, school hours, the file server, the helpdesk set-up, password policies and lab hosts. After editing it:

```bash
pip install pyyaml
python3 generator/generate.py                       # rewrite the generated files
python3 -m unittest discover -s generator/tests     # sanity checks
./install.sh ../GOAD                                # push the change into GOAD
```

The generator `seed` always produces the same accounts, so every instructor's lab matches and lessons can name accounts.

## Checking a built lab

`verify/verify.py` checks a running lab against the generated files and only reads from it. It covers:

- the OU tree
- every bulk and story account: OU, attributes, manager, groups, logon hours and expiry
- exact group membership and nesting
- a real sign-in attempt for one account of each kind, checked against logon hours at the DC's current time
- domain join and local groups on each member host
- Phase 2:
  - shares, with exact share and NTFS permissions
  - home folders
  - password policies, and which one applies to a sample account
  - school-hours logon schedules
  - helpdesk reset rights, worked out from the ACLs
  - GPO links, settings and drive maps
- share reads and writes made from the student lab PC as a Grade 5 student and as a teacher
- Phase 3:
  - service accounts in `OU=Service Accounts` with the designed SPNs, groups and weaknesses (Kerberoastable SPN, password in the Description)
  - the directory-sync account's DCSync rights on the domain head
  - the honey account: enabled, enumerable, holding no real privilege
  - the SYSVOL logon script (matched by SHA-256) and the `scriptPath` set on staff
  - the ESC1 certificate template (flags, enroll ACL, CA publication) and the MapleGrade SIS (SQL service identity, `Grades` rows, IIS)
- Phase 4:
  - the advanced audit policy in effect on every host (via `auditpol`), for the subcategories the lessons rely on
  - the ELK log agents (Winlogbeat and Sysmon services) running on every domain host, and Elasticsearch up at .50 with Winlogbeat events landing in it

```bash
python3 verify/verify.py --goad ../GOAD --instance <instance id>   # e.g. 4abff6-maplewood-virtualbox
```

It runs `verify/snapshot.yml` through GOAD's inventories and GOAD's Ansible (`~/.goad/.venv`), prints PASS or FAIL for each check, and exits non-zero if anything fails. Options:

- `--out DIR` keeps the snapshot, which contains no passwords.
- When a probe write succeeds, it uses a file that deletes itself on close, so the check leaves nothing behind.
- `--snapshot DIR` re-checks a saved snapshot offline.
- `--phase N` skips checks that belong to later phases.

Each check is a function tagged `@check(phase)` in `verify.py`. Later phases add theirs beside the Phase 1 checks and collect any new state in `snapshot.yml` or `dc_state.ps1`. To test the checks offline against a synthetic perfect build, run `python3 -m unittest discover -s verify/tests`.

## Troubleshooting

To re-run one step after fixing a problem, run that playbook against your instance. The `.yml` suffix is required; without it GOAD reports that the playbook could not be found:

```bash
./goad.sh -t install -l MAPLEWOOD -p virtualbox -i <instance id> -r mw-district.yml
```

- **A Windows 10 VM blue-screens on its first boot and Vagrant times out.** WS02 did this on the reference build (`PAGE_FAULT_IN_NONPAGED_AREA`). Power the VM off in VirtualBox, run `vagrant up MAPLEWOOD-WS02` in `GOAD/workspace/<instance id>/`, then continue with `load <instance id>` and `provision_lab` in `./goad.sh`.
- **A Windows 10 VM shuts itself down every hour.** Its evaluation has expired. `mw-rearm.yml` fixes this and installs a task that keeps it fixed; if it happens before that playbook has run, run it with `-r mw-rearm.yml`.
- **A PowerShell step against DC01 fails with `OutOfMemoryException` right after a reboot.** DC01 has 4 GB. Wait a minute and re-run the playbook (or `verify.py`).
- **The SQL Server install in `servers.yml` fails with a non-zero exit code.** The installer can report an error even when SQL Server is installed. Re-run `servers.yml`: once the SQL service exists the install step is skipped and the configuration completes.
- **`install_extension elk` can't connect to the ELK VM.** Install `sshpass`, as above.

## How it fits into GOAD

| Step (from `playbooks.yml`)                        | Source    | Does                                                                                                                                                                                                                                                                                                                                                                                                        |
| -------------------------------------------------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mw-rearm.yml`                                     | MapleWood | Rearms expired Windows evaluations, then reboots (the `mayfly/windows10` box's evaluation has expired, which makes Windows shut down every hour). It sets `SkipRearm` first so the rearm count is never consumed, and installs an in-guest scheduled task (`MapleWood Eval Rearm`, SYSTEM, at startup + daily) that rearms unattended so a long-lived lab keeps itself in date without re-running anything. |
| build, ad-servers, ad-parent_domain, ad-members    | GOAD      | Builds VMs, promotes DC01, joins the member hosts                                                                                                                                                                                                                                                                                                                                                           |
| `mw-ou-tree.yml`                                   | MapleWood | Creates the school-based OU tree from `files/ou_tree.json`                                                                                                                                                                                                                                                                                                                                                  |
| ad-data                                            | GOAD      | Creates groups and story accounts from `data/config.json`, moves WS01 to its OU                                                                                                                                                                                                                                                                                                                             |
| `mw-district.yml`                                  | MapleWood | Imports bulk staff and students from `files/users.csv` (incl. `scriptPath`) in one PowerShell run, then applies `files/resources.json`: password policies and home folder attributes (`mw_fgpp`, `mw_home`), shares and home folders on SRV01 (`mw_shares`), GPOs (`mw_gpo`), and DCSync rights for the sync account (`mw_replication`)                                                                     |
| ad-acl                                             | GOAD      | Helpdesk password-reset delegation from `config.json`                                                                                                                                                                                                                                                                                                                                                       |
| vulnerabilities                                    | GOAD      | Places the SYSVOL logon script (`files` vuln) and runs host scripts                                                                                                                                                                                                                                                                                                                                         |
| adcs                                               | GOAD      | Installs the CA on the DC; the vulnerable `MapleWood-WiFi-User` (ESC1) template is installed by the `adcs_templates` vuln                                                                                                                                                                                                                                                                                   |
| servers                                            | GOAD      | Installs IIS and MSSQL Express on SRV01 (SQL runs as `svc-sis`); the `maplegrade_db.ps1` script hook creates the `MapleGrade` database                                                                                                                                                                                                                                                                      |
| laps, ad-relations, security                       | GOAD      | Stock steps                                                                                                                                                                                                                                                                                                                                                                                                 |
| `elk` extension (separate `install_extension elk`) | GOAD      | Builds the ELK VM at .50, installs Elasticsearch/Logstash/Kibana, and installs the Winlogbeat + Sysmon log agents on every domain host (`elk_log:children = domain`)                                                                                                                                                                                                                                        |

GOAD's stock OU step names each OU by itself, so it cannot create a `Teachers` OU under every school; `mw_ou_tree` works from full DNs instead. The bulk import sets attributes GOAD's user step lacks (title, department, office, employee ID, mail, manager, expiry, logon hours) and deletes its CSV from the DC when done.

## Repository layout

```
scenario/district.yml          the one file instructors edit
generator/generate.py          district.yml -> lab/, lessons/ and instructor/answer_key.md
generator/names/               synthetic name lists
generator/tests/               consistency tests
lab/MAPLEWOOD/                 generated GOAD lab (becomes GOAD/ad/MAPLEWOOD)
ansible/                       MapleWood playbooks, roles and the playbooks.yml entry
instructor/answer_key.md       generated answer key: weak passwords, stale accounts, seeded weaknesses
instructor/attack-playbooks/   hand-written attack walkthroughs, one per lesson (seed 2026; not regenerated)
lessons/                       generated blue-team lessons, one per seeded scenario
attacker/                      optional standalone Kali VM (its own Vagrant project, outside GOAD)
verify/                        checks a built lab against the generated files (phase gates)
install.sh                     install, update or remove in a GOAD checkout
LICENSE                        GPL-3.0
```

The attack playbooks name this seed's accounts and passwords. If you change `seed` or the story accounts in `district.yml`, update them by hand.

## A note on secrets

`lab/MAPLEWOOD/files/users.csv`, `data/config.json`, `files/sysvol/logon.bat`, `instructor/answer_key.md` (which also lists the seeded weaknesses) and `instructor/attack-playbooks/` contain lab passwords in plain text, as GOAD's own configs do.

## License

GPL-3.0, the same as GOAD. See [`LICENSE`](LICENSE). 
