# Attacker box (Kali) for MapleWood USD

A small headless Kali VM on the lab's host-only network, for running the attacks the
[`lessons/`](../lessons/) hunt for. The Security/Sysmon/PowerShell telemetry lands in ELK
where you then go find it.

It is **standalone on purpose**: a separate Vagrant project, not part of the GOAD instance. `goad
reset`, GOAD snapshots and rebuilds never touch it, so your tooling and loot survive a lab reset.
It only shares `vboxnet0` (192.168.56.0/24) with the lab, plus NAT for internet.

## Use

```bash
cd attacker
vagrant up            # first run downloads the Kali box (~10 GB); 3 GB RAM, 2 vCPU, headless
vagrant ssh           # user: vagrant / pass: vagrant
vagrant halt          # stop it to free ~3 GB RAM
vagrant up            # start it again
vagrant destroy       # remove it
```

The box already ships `netexec` (`nxc`, 1.5.1) and `nmap`. Install anything else a lesson needs
with apt (wait out the occasional flaky Kali mirror with a second `apt-get update`):

```bash
sudo apt update && sudo apt install -y bloodhound.py python3-impacket impacket-scripts
```

## Name resolution (handled automatically)

Kerberos tools need to resolve the realm and its SRV records (`_kerberos._tcp`, `_ldap._tcp`); the stock box can't, and fails with `Temporary failure in name resolution (…:88)`. The Vagrantfile fixes this on every `vagrant up`/`reload` (provisioner `maplewood-dns`), so there's nothing to do:

- NetworkManager is set `dns=none` (`/etc/NetworkManager/conf.d/90-maplewood-dns.conf`) so it won't  overwrite `/etc/resolv.conf`.
- `/etc/resolv.conf` becomes `search maplewoodusd.local` + `nameserver 192.168.56.30` (the DC) with `nameserver 10.0.2.3` (VirtualBox NAT DNS) as a failover. The DC is authoritative for the domain  **and** recurses to the internet, so both lab names and `apt` work through it; `10.0.2.3` only  kicks in (on timeout) if the DC is down.
- `/etc/hosts` gets the same five hosts as an offline fallback.

Verify after boot: `dig +short SRV _kerberos._tcp.maplewoodusd.local` returns the DC, and
`getent hosts kali.org` still resolves (internet via the DC).

## Smoke test: Kerberoast → find it in Kibana

A one-shot check that the attack path and the telemetry pipeline both work (lesson 03, plus the
honey-account alert from lesson 10 as a bonus). Authenticate as any domain user — e.g.
`nadia.lee` / `Fall2026!` from the [answer key](../instructor/answer_key.md):

```bash
nxc ldap 192.168.56.30 -u nadia.lee -p 'Fall2026!' --kerberoasting /tmp/roast.txt
```

That requests RC4 service tickets for every SPN account — `svc-sis` and, because it also carries an SPN, the `svc-superadmin` honey account — and writes the crackable `$krb5tgs$23$` hashes. Then hunt it in Kibana (`http://192.168.56.50:5601`, index pattern `winlogbeat-*`):

```
winlog.event_id: 4769 and winlog.event_data.TicketEncryptionType: "0x17"
  and winlog.event_data.ServiceName: ("svc-sis" or "svc-superadmin")
```

Each hit carries the requesting user (`winlog.event_data.TargetUserName`) and the attacker's IP in `source.ip` (`192.168.56.99`, this box — a dead giveaway it isn't a normal service host). Any 4769 for `svc-superadmin` is pure signal: nothing legitimately uses that account.

## The lab, from here

| Host                         | IP            | Role                                     |
| ---------------------------- | ------------- | ---------------------------------------- |
| MAPLEWOOD-DC01 (mwdc01)      | 192.168.56.30 | DC, ADCS CA                              |
| MAPLEWOOD-WS01 (mhs-staff01) | 192.168.56.31 | staff workstation                        |
| MAPLEWOOD-SRV01 (mwsrv01)    | 192.168.56.32 | file server + MapleGrade SIS (MSSQL/IIS) |
| MAPLEWOOD-WS02 (mms-lab01)   | 192.168.56.33 | student lab PC                           |
| ELK                          | 192.168.56.50 | Elasticsearch/Kibana (Kibana `:5601`)    |
| MAPLEWOOD-KALI               | 192.168.56.99 | **this box**                             |

Domain `maplewoodusd.local` (NetBIOS `MAPLEWOOD`). Account names, passwords and the per-lesson targets are in [`../instructor/answer_key.md`](../instructor/answer_key.md) and the lessons.

## RAM note

The five lab VMs commit ~22 GB; the host recommendation is 32 GB. If you need more room, `vagrant halt` the student lab PC (WS02, 4 GB) while you work, or `vagrant halt` this box when you're done.

> Lab only. Like the rest of MapleWood, keep this off the internet-facing side and never point it at
> anything but the lab.
