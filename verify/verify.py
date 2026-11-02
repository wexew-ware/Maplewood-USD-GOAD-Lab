#!/usr/bin/env python3
"""Check a built MapleWood lab against the generated files in lab/MAPLEWOOD/ (the phase gates).

  python3 verify/verify.py --goad ../GOAD --instance <id>   snapshot the running lab, then check it
  python3 verify/verify.py --snapshot DIR                     re-check a snapshot saved with --out

A snapshot runs verify/snapshot.yml with GOAD's own inventories. DC01 reports its OUs, users,
groups, computers, password policies, helpdesk reset rights and GPOs and tries one sign-in per
kind of account; every other domain host reports its domain membership, local groups and shares;
the student lab workstation tries a few share reads and writes as sample accounts. Nothing in the
lab is changed (a probe write that succeeds uses a delete-on-close file). Passwords go to Ansible
in a 0600 temp file and never reach the logs or the snapshot.

Each check is a generator function registered with @check(phase) that yields (ok, label, detail).
Expectations that depend on the time of day (logon hours) use the DC's clock from the snapshot.
Exit 0 when every check passes.
"""
from __future__ import annotations

import argparse
import collections
import csv
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HERE = Path(__file__).resolve().parent
LAB = "MAPLEWOOD"
GOAD_VENV_PLAYBOOK = Path.home() / ".goad" / ".venv" / "bin" / "ansible-playbook"
NO_HOURS = "00" * 21
DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]


# --- inputs ---------------------------------------------------------------------------------

def load_lab(root: Path = ROOT) -> dict:
    lab = root / "lab" / LAB
    config = json.loads((lab / "data" / "config.json").read_text())["lab"]
    domain_name, domain = next(iter(config["domains"].items()))
    with open(lab / "files" / "users.csv", newline="") as f:
        rows = list(csv.DictReader(f))
    resources = lab / "files" / "resources.json"
    return {"rows": rows, "tree": json.loads((lab / "files" / "ou_tree.json").read_text()),
            "hosts": config["hosts"], "domain_name": domain_name, "domain": domain,
            "resources": json.loads(resources.read_text()) if resources.exists() else None}


def load_snapshot(path: Path) -> dict:
    probes, sis, elk = path / "share_probes.json", path / "sis.json", path / "elk.json"
    return {"dc": json.loads((path / "dc_state.json").read_text()),
            "signin": json.loads((path / "signin.json").read_text()),
            "probes": json.loads(probes.read_text()) if probes.exists() else None,
            "sis": json.loads(sis.read_text()) if sis.exists() else None,
            "elk": json.loads(elk.read_text()) if elk.exists() else None,
            "hosts": {p.stem[len("host_"):]: json.loads(p.read_text()) for p in sorted(path.glob("host_*.json"))},
            "agents": {p.stem[len("agents_"):]: json.loads(p.read_text()) for p in sorted(path.glob("agents_*.json"))}}


def parent(dn: str) -> str:
    return re.split(r"(?<!\\),", dn, maxsplit=1)[1]


def ou_label(path: str) -> str:
    """'OU=Teachers,OU=Staff,OU=Maplewood High,DC=..' -> 'Maplewood High/Staff/Teachers'"""
    return "/".join(reversed([p[3:] for p in re.split(r"(?<!\\),", path) if p.startswith("OU=")]))


def csv_hours(value: str) -> str:
    """users.csv LogonHours ('none', 42 hex digits or '') in the form dc_state.ps1 reports."""
    return NO_HOURS if value == "none" else value.lower()


def logon_allowed(hours: str, now: datetime.datetime) -> bool:
    """Whether a logonHours value ('' = unrestricted) permits signing in at UTC time `now`."""
    if not hours:
        return True
    i = (now.weekday() + 1) % 7 * 24 + now.hour   # AD's week starts Sunday 00:00 UTC
    return bool(bytes.fromhex(hours)[i // 8] >> (i % 8) & 1)


def snapshot_time(snap: dict) -> datetime.datetime:
    return datetime.datetime.strptime(snap["dc"]["utc_now"], "%Y-%m-%dT%H:%M:%SZ")


def account_groups(lab: dict) -> dict[str, set[str]]:
    """sam -> every group (lowercase) it belongs to, directly or through nesting."""
    parents = collections.defaultdict(set)
    for groups in lab["domain"]["groups"].values():
        for name, spec in groups.items():
            for m in spec.get("members", []):
                parents[m.lower()].add(name.lower())
    direct = {r["SamAccountName"]: [g for g in r["Groups"].split(";") if g] for r in lab["rows"]}
    direct.update({sam: u.get("groups", []) for sam, u in lab["domain"]["users"].items()})
    out = {}
    for sam, groups in direct.items():
        seen, todo = set(), [g.lower() for g in groups]
        while todo:
            g = todo.pop()
            if g not in seen:
                seen.add(g)
                todo += parents[g]
        out[sam.lower()] = seen
    return out


def account_paths(lab: dict) -> dict[str, str]:
    paths = {r["SamAccountName"].lower(): r["Path"] for r in lab["rows"]}
    paths.update({sam.lower(): u["path"] for sam, u in lab["domain"]["users"].items()})
    return paths


def reset_expected(lab: dict, actor: str, target: str) -> bool:
    """Whether the generated ACLs let actor reset target's password. Domain Admins members are
    protected: AdminSDHolder strips inherited ACEs from them."""
    groups, path = account_groups(lab), account_paths(lab)[target.lower()].lower()
    if "domain admins" in groups[target.lower()]:
        return False
    return any(acl["right"] == "Ext-User-Force-Change-Password" and acl["for"].lower() in groups[actor.lower()]
               and (path == acl["to"].lower() or path.endswith("," + acl["to"].lower()))
               for acl in lab["domain"]["acls"].values())


def policy_expected(lab: dict, sam: str) -> str:
    """The fine-grained password policy that should apply to sam ('' = the domain policy)."""
    groups = account_groups(lab)[sam.lower()]
    applicable = [p for p in lab["resources"]["password_policies"] if groups & {g.lower() for g in p["applies_to"]}]
    return min(applicable, key=lambda p: p["precedence"])["name"] if applicable else ""


def expected_access(lab: dict, sam: str, share: dict, op: str) -> bool:
    """Share permission AND NTFS permission at the share root, from resources.json."""
    groups = account_groups(lab)[sam.lower()] | {"everyone", "authenticated users"}
    held = lambda perms: {level for who, level in perms.items() if who.split("\\")[-1].lower() in groups}
    ntfs, smb = held(share["ntfs"]), held(share["share_access"])
    if op == "read":
        return bool(ntfs) and bool(smb)
    return bool(ntfs & {"modify", "full"}) and bool(smb & {"Change", "Full"})


# --- what to sample -------------------------------------------------------------------------

def signin_samples(lab: dict) -> list[dict]:
    """The first CSV account of each kind (OU, enabled, logon hours, expiry) plus every story account."""
    samples, seen = [], set()
    for r in lab["rows"]:
        kind = (r["Path"], r["Enabled"], r["LogonHours"], bool(r["AccountExpires"]))
        if kind in seen:
            continue
        seen.add(kind)
        enabled = r["Enabled"].lower() == "true"
        notes = [n for n, on in [("disabled", not enabled), ("no logon hours", r["LogonHours"] == "none"),
                                 ("school hours", r["LogonHours"] not in ("", "none")),
                                 (f"expires {r['AccountExpires']}", bool(r["AccountExpires"]))] if on]
        samples.append({"sam": r["SamAccountName"], "password": r["Password"], "enabled": enabled,
                        "expires": r["AccountExpires"], "hours": csv_hours(r["LogonHours"]),
                        "kind": ou_label(r["Path"]) + (f" ({', '.join(notes)})" if notes else "")})
    # The honey account is deliberately left out: verify must not authenticate as the tripwire.
    honey = set((lab["resources"] or {}).get("honey_accounts", []))
    for sam, u in lab["domain"]["users"].items():
        if sam in honey:
            continue
        samples.append({"sam": sam, "password": u["password"], "enabled": True, "expires": "", "hours": "",
                        "kind": "story account"})
    return samples


def signin_expected(sample: dict, now: datetime.datetime) -> bool:
    # accountExpires is midnight at the start of that date, so the account is dead that day.
    expired = bool(sample["expires"]) and datetime.date.fromisoformat(sample["expires"]) <= now.date()
    return sample["enabled"] and not expired and logon_allowed(sample["hours"], now)


def build_plan(lab: dict) -> dict:
    """Everything the snapshot needs to sample, derived from the lab files."""
    plan = {"signins": signin_samples(lab), "rsop_sams": [], "reset_pairs": [], "probe_host": None, "probes": [],
            "repl_sams": [], "sysvol_paths": [], "adcs_template": "", "sis": None}
    res = lab["resources"]
    if not res:
        return plan
    plan["repl_sams"] = list(res.get("replication_rights", []))
    if res.get("logon_script"):
        plan["sysvol_paths"] = [res["logon_script"]["netlogon_path"]]
    plan["adcs_template"] = res.get("adcs", {}).get("template", "")
    plan["sis"] = res.get("sis")
    groups = account_groups(lab)
    live = [r for r in lab["rows"] if r["Enabled"] == "true" and ",OU=Disabled," not in r["Path"]]
    candidates = [r["SamAccountName"] for r in live] + list(lab["domain"]["users"])
    resolved = {sam: policy_expected(lab, sam) for sam in candidates}
    for p in res["password_policies"]:
        sam = next((s for s in candidates if resolved[s] == p["name"]), None)   # first account it wins for
        if sam:
            plan["rsop_sams"].append(sam)

    actors = [sam for sam, u in lab["domain"]["users"].items() if any(g.endswith("-HelpDesk") for g in u.get("groups", []))]
    targets = []
    for students_ou in (o["dn"] for o in lab["tree"] if o["name"] == "Students"):
        school = parent(students_ou)
        targets += [next(r["SamAccountName"] for r in live if r["Path"].endswith("," + students_ou)),
                    next(r["SamAccountName"] for r in live if r["Path"] == f"OU=Teachers,OU=Staff,{school}")]
        targets += [sam for sam, u in lab["domain"]["users"].items() if u["path"] == f"OU=Staff,{school}"]
    targets += [sam for sam, u in lab["domain"]["users"].items() if "Domain Admins" in u.get("groups", [])]
    plan["reset_pairs"] = [{"actor": a, "target": t} for a in actors for t in targets]

    probe_host = next((k for k, h in lab["hosts"].items() if h["type"] == "workstation" and "OU=Student Labs," in h["path"]), None)
    grade_shares = [s for s in res["shares"] if s.get("drive", {}).get("group", "").startswith("SG-Grade")]
    if probe_host and len(grade_shares) > 1:
        share = next((s for s in grade_shares if s["drive"]["group"] == "SG-Grade05"), grade_shares[0])
        other = grade_shares[(grade_shares.index(share) + 1) % len(grade_shares)]
        rw_members = {m.lower() for dl, members in share["groups"].items() if dl.endswith("-RW") for m in members}
        student = next(r for r in live if share["drive"]["group"] in r["Groups"].split(";"))
        teacher = next(r for r in live if r["Title"] != "Student" and groups[r["SamAccountName"].lower()] & rw_members)
        staff_share = next(s for s in res["shares"] if s["name"].endswith("-Staff$")
                           and not expected_access(lab, student["SamAccountName"], s, "read"))
        open_share = next((s for s in res["shares"] if s.get("seeded_weakness")), None)
        unc = lambda s: f"\\\\{res['file_server']['hostname']}\\{s['name']}"
        tries = [(student, share, "read"), (student, share, "write"), (student, other, "read"),
                 (student, staff_share, "read"), (teacher, share, "read"), (teacher, share, "write")]
        if open_share:
            tries.append((student, open_share, "read"))
        plan["probe_host"] = probe_host
        plan["probes"] = [{"sam": r["SamAccountName"], "password": r["Password"], "unc": unc(s), "op": op,
                           "share": s["name"], "hours": csv_hours(r["LogonHours"]), "who": r["Title"]} for r, s, op in tries]
    return plan


def take_snapshot(lab: dict, plan: dict, goad: Path, instance: str, out: Path, playbook_bin: str) -> None:
    inventories = [goad / "ad" / LAB / "data" / "inventory", goad / "workspace" / instance / "inventory",
                   goad / "globalsettings.ini"]
    for inv in inventories:
        if not inv.is_file():
            sys.exit(f"error: {inv} not found (is {goad} a GOAD checkout with instance {instance}?)")
    res = lab["resources"] or {}
    elk = res.get("elk") or {}
    elk_services = elk.get("agents", []) if elk else []
    elk_host = "none"
    elk_inv = goad / "workspace" / instance / "elk_inventory"
    if elk and elk_inv.is_file():
        m = re.search(r"\bansible_host=(\S+)", elk_inv.read_text())
        if m:
            elk_host = m.group(1)
    with tempfile.TemporaryDirectory() as tmp:
        vars_file = Path(tmp) / "vars.json"
        fd = os.open(vars_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"out_dir": str(out), "mw_domain": lab["domain_name"],
                       "signin_samples": [{"sam": s["sam"], "password": s["password"]} for s in plan["signins"]],
                       "mw_reset_pairs": plan["reset_pairs"], "mw_rsop_sams": plan["rsop_sams"],
                       "mw_gpos": [{"name": g["name"], "links": g["links"], "registry": g["registry"]} for g in res.get("gpos", [])],
                       "mw_repl_sams": plan["repl_sams"], "mw_sysvol_paths": plan["sysvol_paths"],
                       "mw_adcs_template": plan["adcs_template"],
                       "mw_sis_host": (plan["sis"] or {}).get("host", "none"),
                       "mw_sis_sa_password": lab["hosts"].get((plan["sis"] or {}).get("host", ""), {}).get("mssql", {}).get("sa_password", ""),
                       "mw_sis_db": (plan["sis"] or {}).get("db_name", ""),
                       "mw_probe_host": plan["probe_host"] or "none",
                       "mw_probes": [{k: p[k] for k in ("sam", "password", "unc", "op")} for p in plan["probes"]],
                       "mw_elk_services": elk_services,
                       "mw_elk_host": elk_host,
                       "mw_elk_es_port": elk.get("elasticsearch_port", 9200)}, f)
        cmd = [playbook_bin]
        for inv in inventories:
            cmd += ["-i", str(inv)]
        cmd += [str(HERE / "snapshot.yml"), "-e", f"@{vars_file}"]
        proc = subprocess.run(cmd, cwd=goad / "ansible", capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout[-6000:], proc.stderr[-2000:], sep="\n", file=sys.stderr)
        sys.exit(f"error: snapshot playbook failed (exit {proc.returncode}); output above")


# --- checks ---------------------------------------------------------------------------------

CHECKS: list[tuple[int, object]] = []


def check(phase: int):
    def register(fn):
        CHECKS.append((phase, fn))
        return fn
    return register


def users_by_sam(snap: dict) -> dict:
    return {u["sam"].lower(): u for u in snap["dc"]["users"]}


@check(1)
def domain_identity(lab, snap, plan):
    dc, want = snap["dc"], (lab["domain_name"], lab["domain"]["netbios_name"])
    yield (dc["dns_root"], dc["netbios"]) == want, f"domain is {want[0]} / {want[1]}", f"got {dc['dns_root']} / {dc['netbios']}"


@check(1)
def ou_tree(lab, snap, plan):
    missing = {o["dn"].lower() for o in lab["tree"]} - {o.lower() for o in snap["dc"]["ous"]}
    yield not missing, f"all {len(lab['tree'])} OUs from ou_tree.json exist", f"missing {sorted(missing)[:5]}"


@check(1)
def bulk_users(lab, snap, plan):
    users = users_by_sam(snap)
    dn_to_sam = {u["dn"].lower(): u["sam"] for u in snap["dc"]["users"]}
    problems, example = collections.Counter(), {}
    for r in lab["rows"]:
        u = users.get(r["SamAccountName"].lower())
        diffs = ["missing"] if u is None else []
        if u is not None:
            if parent(u["dn"]).lower() != r["Path"].lower(): diffs.append("OU")
            if u["enabled"] != (r["Enabled"].lower() == "true"): diffs.append("enabled")
            for col, key in [("Title", "title"), ("Department", "department"), ("Office", "office"),
                             ("Company", "company"), ("EmployeeID", "employee_id"), ("Mail", "mail")]:
                if (u[key] or "") != r[col]: diffs.append(key)
            if dn_to_sam.get((u["manager"] or "").lower(), "").lower() != r["Manager"].lower(): diffs.append("manager")
            if not {g.lower() for g in r["Groups"].split(";") if g} <= {g.lower() for g in u["member_of"]}: diffs.append("groups")
            if u["logon_hours"] != csv_hours(r["LogonHours"]): diffs.append("logon hours")
            if u["expires"] != r["AccountExpires"]: diffs.append("expiry")
        for d in diffs:
            problems[d] += 1
            example.setdefault(d, r["SamAccountName"])
    yield (not problems, f"all {len(lab['rows'])} bulk users match users.csv (OU, enabled, attributes, manager, groups, logon hours, expiry)",
           ", ".join(f"{k}: {n} e.g. {example[k]}" for k, n in problems.items()))


@check(1)
def story_accounts(lab, snap, plan):
    users, bad = users_by_sam(snap), []
    for sam, s in lab["domain"]["users"].items():
        u = users.get(sam.lower())
        if u is None or parent(u["dn"]).lower() != s["path"].lower() \
                or not {g.lower() for g in s.get("groups", [])} <= {g.lower() for g in u["member_of"]}:
            bad.append(sam)
    yield not bad, f"all {len(lab['domain']['users'])} story accounts exist in their OU and groups", f"wrong: {bad}"


@check(1)
def ou_population(lab, snap, plan):
    """Grade and Teachers OUs hold exactly the CSV's accounts (nothing missing, nothing extra)."""
    want = collections.Counter(r["Path"].lower() for r in lab["rows"])
    have = collections.Counter(parent(u["dn"]).lower() for u in snap["dc"]["users"])
    for label, pick in [("students", lambda o: re.fullmatch(r"Grade(PK|K|\d+)", o["name"])),
                        ("teachers", lambda o: o["name"] == "Teachers")]:
        ous = [o["dn"].lower() for o in lab["tree"] if pick(o)]
        wrong = {ou_label(o): f"{have[o]} (want {want[o]})" for o in ous if have[o] != want[o]}
        per = sorted({want[o] for o in ous})
        yield (not wrong, f"{sum(want[o] for o in ous)} {label} across {len(ous)} OUs ({'/'.join(map(str, per))} per OU)",
               json.dumps(wrong))


@check(1)
def account_restrictions(lab, snap, plan):
    users = users_by_sam(snap)
    no_logon = [r["SamAccountName"] for r in lab["rows"] if r["LogonHours"] == "none"]
    yield (all(users.get(s.lower(), {}).get("logon_hours") == NO_HOURS for s in no_logon),
           f"{len(no_logon)} accounts with no permitted logon hours (Pre-K and K)", "")
    expiring = [r for r in lab["rows"] if r["AccountExpires"]]
    yield (all(users.get(r["SamAccountName"].lower(), {}).get("expires") == r["AccountExpires"] for r in expiring),
           f"{len(expiring)} accounts expire on {', '.join(sorted({r['AccountExpires'] for r in expiring}))} (named substitutes)", "")
    stale = [r for r in lab["rows"] if "OU=Disabled," in r["Path"] and r["Enabled"].lower() == "true"]
    yield (all(users.get(r["SamAccountName"].lower(), {}).get("enabled") for r in stale),
           f"{len(stale)} graduated/former-staff accounts left enabled, as seeded", "")


@check(1)
def groups_exact(lab, snap, plan):
    """Every group the generator defines exists in its OU with its scope and exactly the members it should have."""
    want_users = collections.defaultdict(set)
    for r in lab["rows"]:
        for g in filter(None, r["Groups"].split(";")):
            want_users[g.lower()].add(r["SamAccountName"].lower())
    for sam, u in lab["domain"]["users"].items():
        for g in u.get("groups", []):
            want_users[g.lower()].add(sam.lower())
    have_users, have_groups = collections.defaultdict(set), collections.defaultdict(set)
    for u in snap["dc"]["users"]:
        for g in u["member_of"]:
            have_users[g.lower()].add(u["sam"].lower())
    ad_groups = {g["name"].lower(): g for g in snap["dc"]["groups"]}
    for g in snap["dc"]["groups"]:
        for p in g["member_of"]:
            have_groups[p.lower()].add(g["name"].lower())
    defined = {name: (scope, spec) for scope, groups in lab["domain"]["groups"].items() for name, spec in groups.items()}
    wrong = []
    for name, (scope, spec) in defined.items():
        g, key = ad_groups.get(name.lower()), name.lower()
        if g is None:
            wrong.append(f"{name}: missing"); continue
        if g["scope"].lower() != scope.lower(): wrong.append(f"{name}: scope {g['scope']}")
        if parent(g["dn"]).lower() != spec["path"].lower(): wrong.append(f"{name}: in {parent(g['dn'])}")
        if have_users[key] != want_users[key]:
            wrong.append(f"{name}: users +{sorted(have_users[key] - want_users[key])[:3]} -{sorted(want_users[key] - have_users[key])[:3]}")
        want_nested = {m.lower() for m in spec.get("members", [])}
        if have_groups[key] != want_nested:
            wrong.append(f"{name}: nested groups +{sorted(have_groups[key] - want_nested)} -{sorted(want_nested - have_groups[key])}")
    yield not wrong, f"all {len(defined)} generated groups have the right OU, scope, users and nested groups", "; ".join(wrong[:8])


@check(1)
def signins(lab, snap, plan):
    now = snapshot_time(snap)
    got = {s["sam"].lower(): s for s in snap["signin"]}
    wrong, refused = [], 0
    for s in plan["signins"]:
        expect = signin_expected(s, now)
        refused += not expect
        r = got.get(s["sam"].lower())
        if r is None or r.get("error") or r["accepted"] is not expect:
            outcome = "no result" if r is None else f"error: {r['error']}" if r.get("error") else \
                "accepted" if r["accepted"] else "refused"
            wrong.append(f"{s['sam']} [{s['kind']}]: {outcome}, want {'accepted' if expect else 'refused'}")
    yield (not wrong, f"{len(plan['signins'])} sample sign-ins behave as designed at {now:%a %H:%M} UTC "
           f"({refused} refused: disabled, outside logon hours or expired)", "; ".join(wrong))


@check(1)
def import_cleanup(lab, snap, plan):
    yield not snap["dc"]["csv_left_on_dc"], "users.csv removed from the DC after import", ""


@check(1)
def member_hosts(lab, snap, plan):
    computers = {c["name"].lower(): c for c in snap["dc"]["computers"]}
    for key, h in lab["hosts"].items():
        if h["type"] == "dc":
            continue
        comp = computers.get(h["hostname"].lower())
        yield (comp is not None and parent(comp["dn"]).lower() == h["path"].lower(),
               f"{h['hostname']} computer object in {ou_label(h['path'])}", f"got {comp and comp['dn']}")
        state = snap["hosts"].get(key)
        if state is None:
            yield False, f"{key} snapshot taken", "no host snapshot (host down or missing from the inventory?)"
            continue
        yield (state["part_of_domain"] and state["domain"].lower() == lab["domain_name"] and state["secure_channel"],
               f"{key} joined to {lab['domain_name']} with a healthy secure channel", json.dumps({k: state[k] for k in ("domain", "secure_channel")}))
        local_groups = {g.lower(): ms for g, ms in state["local_groups"].items()}
        for group, members in h.get("local_groups", {}).items():
            have = {m.lower() for m in local_groups.get(group.lower(), [])}
            missing = [m for m in members if m.lower() not in have]
            yield not missing, f"{key} local group '{group}' has {', '.join(members)}", f"missing {missing}"


def ntfs_level(rights: str) -> str:
    return "full" if "FullControl" in rights else "modify" if "Modify" in rights else \
        "read" if "ReadAndExecute" in rights else rights


@check(2)
def file_shares(lab, snap, plan):
    res = lab["resources"]
    if not res:
        return
    fs = res["file_server"]
    state = snap["hosts"].get(fs["host"])
    if state is None:
        yield False, f"{fs['hostname']} file server snapshot taken", "no host snapshot"
        return
    have = {s["name"].lower(): s for s in state["shares"]}
    wrong = []
    for sh in res["shares"]:
        s = have.get(sh["name"].lower())
        if s is None:
            wrong.append(f"{sh['name']}: missing"); continue
        if s["path"].lower() != sh["path"].lower(): wrong.append(f"{sh['name']}: path {s['path']}")
        access = {a["account"].lower(): a["right"] for a in s["access"]}
        if access != {k.lower(): v for k, v in sh["share_access"].items()}: wrong.append(f"{sh['name']}: share access {access}")
        ntfs = {a["identity"].lower(): ntfs_level(a["rights"]) for a in s["ntfs"] if a["type"] == "Allow"}
        if not s["protected"] or ntfs != {k.lower(): v for k, v in sh["ntfs"].items()}:
            wrong.append(f"{sh['name']}: NTFS {'inherits' if not s['protected'] else ntfs}")
        if sh.get("home") and s["enumeration"] != "AccessBased": wrong.append(f"{sh['name']}: no access-based enumeration")
    yield (not wrong, f"{len(res['shares'])} shares on {fs['hostname']} with exactly the designed share and NTFS permissions",
           "; ".join(wrong[:6]))
    for sh in res["shares"]:
        if sh.get("seeded_weakness"):
            s = have.get(sh["name"].lower(), {})
            open_ = any(a["account"] == "Everyone" for a in s.get("access", [])) and \
                any(a["identity"] == "Everyone" and ntfs_level(a["rights"]) == "full" for a in s.get("ntfs", []))
            yield open_, f"\\\\{fs['hostname']}\\{sh['name']} is {sh['seeded_weakness']} (seeded weakness)", ""


@check(2)
def home_folders(lab, snap, plan):
    res = lab["resources"]
    if not res:
        return
    users = users_by_sam(snap)
    home = next(s for s in res["shares"] if s.get("home"))
    state = snap["hosts"].get(res["file_server"]["host"], {})
    share = next((s for s in state.get("shares", []) if s["name"].lower() == home["name"].lower()), {"children": []})
    folders = {c["name"].lower(): {a["identity"].lower(): ntfs_level(a["rights"]) for a in c["ntfs"]} for c in share["children"]}
    nb = lab["domain"]["netbios_name"].lower()
    wrong = []
    for h in res["home_folders"]:
        u = users.get(h["sam"].lower(), {})
        if u.get("home_directory", "").lower() != h["directory"].lower() or u.get("home_drive") != h["drive"]:
            wrong.append(f"{h['sam']}: AD home {u.get('home_drive')} {u.get('home_directory')}")
        if folders.get(h["sam"].lower(), {}).get(f"{nb}\\{h['sam'].lower()}") != "modify":
            wrong.append(f"{h['sam']}: folder missing or user lacks Modify")
    yield (not wrong, f"{len(res['home_folders'])} staff home folders exist with owner-only access and are mapped as "
           f"{res['home_folders'][0]['drive'] if res['home_folders'] else '-'}", "; ".join(wrong[:6]))


@check(2)
def password_policies(lab, snap, plan):
    res = lab["resources"]
    if not res:
        return
    have = {p["name"]: p for p in snap["dc"]["fgpps"]}
    wrong = []
    for p in res["password_policies"]:
        h = have.get(p["name"])
        if h is None:
            wrong.append(f"{p['name']}: missing"); continue
        max_age = 0 if h["max_age_days"] >= 99999 else h["max_age_days"]
        got = (h["precedence"], h["min_length"], h["complexity"], h["history"], h["lockout_threshold"], max_age)
        want = (p["precedence"], p["min_length"], p["complexity"], p["history"], p["lockout_threshold"], p["max_age_days"])
        if got != want: wrong.append(f"{p['name']}: settings {got}")
        if {s.lower() for s in h["applies_to"]} != {s.lower() for s in p["applies_to"]}: wrong.append(f"{p['name']}: applies to {h['applies_to']}")
    yield not wrong, f"{len(res['password_policies'])} fine-grained password policies with the designed settings and groups", "; ".join(wrong)
    wrong = []
    for sam in plan["rsop_sams"]:
        want = policy_expected(lab, sam)
        got = snap["dc"]["resultant_policies"].get(sam, "<not reported>")
        if got != want:
            wrong.append(f"{sam}: {got or 'domain policy'}, want {want or 'domain policy'}")
    yield not wrong, f"resultant password policy is right for {len(plan['rsop_sams'])} sample accounts (one per policy)", "; ".join(wrong)


@check(2)
def student_logon_hours(lab, snap, plan):
    """Gate: students outside no-logon grades may sign in only during school hours (e.g. refused at 9pm)."""
    res = lab["resources"]
    if not res:
        return
    spec = res["student_logon_hours"]
    users = users_by_sam(snap)
    scheduled = [r for r in lab["rows"] if r["LogonHours"] not in ("", "none")]
    sample = next((r for r in scheduled if r["Path"].startswith("OU=Grade05,")), scheduled[0])
    hours = users.get(sample["SamAccountName"].lower(), {}).get("logon_hours", "")
    off = spec["utc_offset"]
    allowed = set()
    if hours:
        bits = bytes.fromhex(hours)
        allowed = {DAYS[(i + off) % 168 // 24] + f" {(i + off) % 24:02d}" for i in range(168) if bits[i // 8] >> (i % 8) & 1}
    want = {f"{d} {h:02d}" for d in spec["days"] for h in range(spec["start"], spec["end"])}
    yield (allowed == want and "Mon 21" not in allowed,
           f"{sample['SamAccountName']} ({ou_label(sample['Path'])}) may sign in {'/'.join(spec['days'])} "
           f"{spec['start']:02d}:00-{spec['end']:02d}:00 local and is refused at 21:00",
           f"allowed hours: {sorted(allowed)[:6]}{'...' if len(allowed) > 6 else ''}")


@check(2)
def helpdesk_delegation(lab, snap, plan):
    """Gate: each helpdesk resets only its own school's students; the overbroad one (seeded) also resets staff."""
    if not plan["reset_pairs"]:
        return
    paths = account_paths(lab)
    got = {(r["actor"].lower(), r["target"].lower()): r["can_reset"] for r in snap["dc"]["reset_rights"]}
    wrong, granted = [], 0
    for pair in plan["reset_pairs"]:
        a, t = pair["actor"].lower(), pair["target"].lower()
        want = reset_expected(lab, a, t)
        granted += want
        if got.get((a, t)) is not want:
            wrong.append(f"{pair['actor']} -> {pair['target']} ({ou_label(paths[t])}): {got.get((a, t))}, want {want}")
    yield (not wrong, f"helpdesk reset rights match the design for {len(plan['reset_pairs'])} actor/target pairs "
           f"({granted} allowed), e.g. the MES helpdesk cannot reset an MMS student", "; ".join(wrong[:6]))


@check(2)
def group_policy(lab, snap, plan):
    res = lab["resources"]
    if not res:
        return
    have = {g["name"]: g for g in snap["dc"]["gpos"]}
    for g in res["gpos"]:
        h = have.get(g["name"], {"exists": False})
        wrong = []
        if not h["exists"]:
            yield False, f"GPO '{g['name']}' exists", "missing"
            continue
        wrong += [f"not linked/enabled at {l['target']}" for l in h["links"] if not (l["linked"] and l["enabled"])]
        regs = {(r["key"].lower(), r["value_name"].lower()): r for r in h["registry"]}
        for r in g["registry"]:
            got = regs.get((r["key"].lower(), r["value_name"].lower()), {})
            if got.get("value") != str(r["value"]) or got.get("type") != r["type"]:
                wrong.append(f"{r['value_name']}={got.get('value')}")
        want_drives = {(d["letter"], d["path"].lower(), d["group"].lower()) for d in g.get("drives", [])}
        got_drives = {(d["letter"], d["path"].lower(), d["group"].lower()) for d in h["drives"]}
        if want_drives != got_drives: wrong.append(f"drive maps +{sorted(got_drives - want_drives)[:2]} -{sorted(want_drives - got_drives)[:2]}")
        if not all(d["sid_ok"] for d in h["drives"]): wrong.append("drive map group SIDs stale")
        if h["drives"] and "{5794DAFD-BE60-433F-88A2-1A31939AC01F}" not in h["user_extensions"].upper(): wrong.append("Drive Maps extension not registered")
        if h["version_ad"] != h["version_ini"]: wrong.append(f"version AD {h['version_ad']} != GPT.INI {h['version_ini']}")
        what = ", ".join(filter(None, [f"{len(g['registry'])} policy settings" if g["registry"] else "",
                                       f"{len(g.get('drives', []))} group-targeted drive maps" if g.get("drives") else ""]))
        yield not wrong, f"GPO '{g['name']}' linked to {len(g['links'])} target(s) with {what}", "; ".join(wrong[:6])


@check(2)
def share_access(lab, snap, plan):
    """Gate: from the student lab, a Grade 5 student reads but cannot write the Grade 5 share."""
    if not plan["probes"]:
        return
    if snap["probes"] is None:
        yield False, f"share probes ran on {plan['probe_host']}", "no share_probes.json in the snapshot"
        return
    now = snapshot_time(snap)
    res = lab["resources"]
    shares = {s["name"]: s for s in res["shares"]}
    got = {(p["sam"].lower(), p["unc"].lower(), p["op"]): p for p in snap["probes"]}
    wrong, lines = [], []
    for p in plan["probes"]:
        want = logon_allowed(p["hours"], now) and expected_access(lab, p["sam"], shares[p["share"]], p["op"])
        r = got.get((p["sam"].lower(), p["unc"].lower(), p["op"]))
        if r is None or r["allowed"] is not want:
            wrong.append(f"{p['who']} {p['sam']} {p['op']} {p['unc']}: {'no result' if r is None else ('allowed' if r['allowed'] else 'denied: ' + r['error'])}, "
                         f"want {'allowed' if want else 'denied'}")
        lines.append(f"{p['op']} {p['share']} {'ok' if want else 'denied'}")
    yield (not wrong, f"{len(plan['probes'])} share probes from {plan['probe_host']} behave as designed at {now:%a %H:%M} UTC "
           f"(student: {', '.join(l for l, p in zip(lines, plan['probes']) if p['who'] == 'Student')})", "; ".join(wrong))


PRIVILEGED_GROUPS = {"domain admins", "enterprise admins", "administrators", "account operators",
                     "backup operators", "server operators", "schema admins", "group policy creator owners"}


@check(3)
def service_accounts(lab, snap, plan):
    """Service accounts exist in OU=Service Accounts with the designed SPNs, groups and seeded
    weakness (Kerberoastable SPN, or a password written into the Description field)."""
    res = lab["resources"]
    if not res or not res.get("service_accounts"):
        return
    users = users_by_sam(snap)
    defined = lab["domain"]["users"]
    svc_ou = f"OU=Service Accounts,{','.join(f'DC={p}' for p in lab['domain_name'].split('.'))}".lower()
    wrong, kerberoastable = [], 0
    for meta in res["service_accounts"]:
        sam = meta["sam"]
        u, spec = users.get(sam.lower()), defined.get(sam, {})
        if u is None:
            wrong.append(f"{sam}: missing"); continue
        if parent(u["dn"]).lower() != svc_ou:
            wrong.append(f"{sam}: in {parent(u['dn'])}")
        if {s.lower() for s in u["spns"]} != {s.lower() for s in spec.get("spns", [])}:
            wrong.append(f"{sam}: SPNs {u['spns']}")
        if {g.lower() for g in spec.get("groups", [])} - {g.lower() for g in u["member_of"]}:
            wrong.append(f"{sam}: groups {u['member_of']}")
        if meta["weakness"] == "kerberoast":
            if u["spns"] and u["enabled"]:
                kerberoastable += 1
            else:
                wrong.append(f"{sam}: not Kerberoastable (spns={bool(u['spns'])}, enabled={u['enabled']})")
        if meta["weakness"] == "password_in_description" and spec.get("password", "\0") not in u["description"]:
            wrong.append(f"{sam}: password not in description")
    yield (not wrong, f"{len(res['service_accounts'])} service accounts in OU=Service Accounts with the designed SPNs, "
           f"groups and weaknesses ({kerberoastable} Kerberoastable)", "; ".join(wrong[:6]))


@check(3)
def dcsync_rights(lab, snap, plan):
    """Gate: the directory-sync account has DCSync (both replication rights) on the domain head."""
    if not plan["repl_sams"]:
        return
    got = {g["sam"].lower(): g for g in snap["dc"].get("replication_grants", [])}
    wrong = []
    for sam in plan["repl_sams"]:
        g = got.get(sam.lower())
        if not g or not (g["get_changes"] and g["get_changes_all"]):
            wrong.append(f"{sam}: {g and (g['get_changes'], g['get_changes_all'])}")
    yield (not wrong, f"{len(plan['repl_sams'])} account(s) have DCSync rights on the domain head "
           f"(Get-Changes + Get-Changes-All), a seeded DCSync path", "; ".join(wrong))


@check(3)
def honey_account(lab, snap, plan):
    """The decoy admin exists and looks tempting (enabled, has an SPN) but holds no real privilege."""
    res = lab["resources"]
    if not res or not res.get("honey_accounts"):
        return
    users = users_by_sam(snap)
    for sam in res["honey_accounts"]:
        u = users.get(sam.lower())
        problems = []
        if u is None:
            problems.append("missing")
        else:
            if not u["enabled"]:
                problems.append("disabled")
            if not u["spns"]:
                problems.append("no SPN (not enumerable as bait)")
            priv = {g.lower() for g in u["member_of"]} & PRIVILEGED_GROUPS
            if priv:
                problems.append(f"actually privileged: {sorted(priv)}")
        yield not problems, f"honey account {sam} is enabled bait with no real privilege", "; ".join(problems)


@check(3)
def logon_script(lab, snap, plan):
    """Gate: the SYSVOL logon script (with a hardcoded password) is deployed and set on staff."""
    res = lab["resources"]
    if not res or not res.get("logon_script"):
        return
    ls = res["logon_script"]
    local = ROOT / "lab" / LAB / "files" / "sysvol" / ls["filename"]
    want_hash = hashlib.sha256(local.read_bytes()).hexdigest()
    sysvol = {f["path"].lower(): f for f in snap["dc"].get("sysvol_files", [])}
    f = sysvol.get(ls["netlogon_path"].lower())
    ok = bool(f and f["exists"] and f["sha256"] == want_hash)
    yield ok, f"SYSVOL logon script {ls['filename']} deployed to NETLOGON with the embedded {ls['embeds']} credentials", \
        ("missing" if not (f and f["exists"]) else f"sha256 {f['sha256'][:12]} != {want_hash[:12]}")
    users = users_by_sam(snap)
    want = {r["SamAccountName"].lower(): r["ScriptPath"] for r in lab["rows"]}
    wrong = [r["SamAccountName"] for r in lab["rows"]
             if users.get(r["SamAccountName"].lower(), {}).get("script_path", "") != r["ScriptPath"]]
    set_count = sum(bool(v) for v in want.values())
    yield (not wrong, f"scriptPath set to {ls['filename']} on {set_count} staff accounts and empty on the rest",
           f"{len(wrong)} wrong e.g. {wrong[:3]}")


CLIENT_AUTH_EKU = "1.3.6.1.5.5.7.3.2"


@check(3)
def adcs_template(lab, snap, plan):
    """Gate: ADCS is installed and the Wi-Fi template is published and ESC1-vulnerable (any domain
    user can enroll and supply their own subject with a client-authentication EKU)."""
    if not plan["adcs_template"]:
        return
    a = snap["dc"].get("adcs")
    if not a:
        yield False, f"ADCS template {plan['adcs_template']} present", "no adcs data in the snapshot"
        return
    enrollers = {i.split("\\")[-1].lower() for i in a["enroll_identities"]}
    problems = []
    if not a["ca_installed"]:
        problems.append("no enterprise CA")
    if not a["exists"]:
        problems.append("template missing")
    else:
        if not a["name_flag"] & 1:
            problems.append("no ENROLLEE_SUPPLIES_SUBJECT")
        if CLIENT_AUTH_EKU not in a["eku"]:
            problems.append(f"no client-auth EKU ({a['eku']})")
        if a["enrollment_flag"] != 0:
            problems.append("manager approval required")
        if a["ra_signature"] != 0:
            problems.append("authorized signatures required")
        if "domain users" not in enrollers:
            problems.append(f"Domain Users cannot enroll ({sorted(enrollers)})")
        if not a["published"]:
            problems.append("not published on the CA")
    yield (not problems, f"ADCS template {plan['adcs_template']} is published and ESC1-vulnerable "
           f"(Domain Users enroll + supply subject + client-auth EKU)", "; ".join(problems))


@check(3)
def sis_server(lab, snap, plan):
    """Gate: the MapleGrade SIS - MSSQL running as svc-sis with the Grades table, and IIS serving."""
    if not plan["sis"]:
        return
    s = snap.get("sis")
    if s is None:
        yield False, f"SIS facts from {plan['sis']['host']}", "no sis.json in the snapshot"
        return
    acct = plan["sis"]["service_account"].lower()
    problems = []
    if s["sql_state"] != "Running":
        problems.append(f"SQL {s['sql_state']}")
    if not s["sql_account"].lower().endswith("\\" + acct) and not s["sql_account"].lower().endswith(acct):
        problems.append(f"SQL runs as {s['sql_account']}, not {acct}")
    if s["db_exists"] != "yes":
        problems.append(f"{plan['sis']['db_name']} database missing")
    if s["grades_rows"] <= 0:
        problems.append("Grades table empty")
    if s["web_status"] != 200:
        problems.append(f"IIS status {s['web_status']}")
    yield (not problems, f"MapleGrade SIS up: MSSQL as {acct} with {s['grades_rows']} Grades rows "
           f"(audit {'on' if s['audit'] else 'off'}), IIS {s['web_status']}", "; ".join(problems))


AUDIT_SETTING_NAMES = {0: "No Auditing", 1: "Success", 2: "Failure", 3: "Success and Failure"}


@check(4)
def audit_policy(lab, snap, plan):
    """Gate: the audit-policy GPO has put the Security-log subcategories the lessons rely on
    (Kerberos tickets, DS access, detailed file share, ...) into effect on every host."""
    res = lab["resources"]
    if not res:
        return
    gpo = next((g for g in res["gpos"] if g.get("audit")), None)
    if not gpo:
        return
    want = {a["subcategory"]: AUDIT_SETTING_NAMES[a["value"]] for a in gpo["audit"]}
    reporters = {"dc01": snap["dc"].get("audit_policy")}
    reporters.update({k: h.get("audit_policy") for k, h in snap["hosts"].items()})
    reporters = {k: v for k, v in reporters.items() if v is not None}   # {} means collected but empty = a failure
    wrong = []
    for host, have in reporters.items():
        for sub, setting in want.items():
            if have.get(sub) != setting:
                wrong.append(f"{host}/{sub}={have.get(sub)!r} (want {setting!r})")
    yield (not wrong and len(reporters) > 0,
           f"audit policy '{gpo['name']}' effective on {len(reporters)} hosts: "
           f"{len(want)} subcategories incl. Kerberos tickets (4769), DS access (4662), detailed file share (5145)",
           "; ".join(wrong[:6]) or ("no host reported audit policy" if not reporters else ""))


@check(4)
def log_agents(lab, snap, plan):
    """Gate: GOAD's elk extension runs its log agents (Winlogbeat, Sysmon) on every domain host,
    so Windows and Sysmon events ship to Elasticsearch."""
    elk = (lab["resources"] or {}).get("elk")
    if not elk:
        return
    agents = snap.get("agents") or {}
    if not agents:
        yield False, "ELK log-agent state collected from the hosts", "no agents_*.json (snapshot didn't reach the hosts, or ELK not installed)"
        return
    for host in sorted(agents):
        svcs = {s["name"]: s for s in agents[host].get("services", [])}
        for name in elk["agents"]:
            s = svcs.get(name, {})
            yield s.get("status") == "Running", f"{host}: '{name}' service running", f"{name} is {s.get('status') or 'absent'}"


@check(4)
def elk_server(lab, snap, plan):
    """Gate: Elasticsearch is up on the ELK box and Winlogbeat events are landing in it."""
    elk = (lab["resources"] or {}).get("elk")
    if not elk:
        return
    state = snap.get("elk")
    if not state or not state.get("queried"):
        yield False, "ELK server queried", "no elk.json / ELK server not located in the instance (is the elk extension installed?)"
        return
    if not state.get("reachable"):
        yield False, f"Elasticsearch reachable on :{elk['elasticsearch_port']}", "no 200 from /_cluster/health (ELK box down?)"
        return
    status = (state.get("health") or {}).get("status")
    yield status in ("green", "yellow"), f"Elasticsearch cluster health is {status or '?'}", f"status {status!r}"
    idx = state.get("indices") or []
    docs = sum(int(i.get("docs.count") or 0) for i in idx)
    yield docs > 0, f"Winlogbeat events in Elasticsearch ({docs} docs across {len(idx)} index(es))", "no winlogbeat-* documents yet"


def run_checks(lab: dict, snap: dict, plan: dict, max_phase: int | None = None) -> list[tuple[int, str, bool, str, str]]:
    """(phase, check name, ok, label, detail) for every result of every check up to max_phase."""
    return [(phase, fn.__name__, bool(ok), label, detail) for phase, fn in CHECKS
            if max_phase is None or phase <= max_phase for ok, label, detail in fn(lab, snap, plan)]


# --- main -----------------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--goad", type=Path, help="GOAD checkout the lab was installed from (needs --instance)")
    src.add_argument("--snapshot", type=Path, help="check a snapshot directory saved earlier with --out")
    ap.add_argument("--instance", help="GOAD instance id, e.g. 4abff6-maplewood-virtualbox")
    ap.add_argument("--out", type=Path, help="keep the snapshot JSON here (default: a temp dir, deleted)")
    ap.add_argument("--phase", type=int, help="only run checks for this phase and earlier (default: all)")
    ap.add_argument("--ansible-playbook", default=str(GOAD_VENV_PLAYBOOK) if GOAD_VENV_PLAYBOOK.exists() else "ansible-playbook",
                    help="ansible-playbook to run (default: GOAD's venv)")
    args = ap.parse_args(argv)

    lab = load_lab()
    plan = build_plan(lab)
    if args.snapshot:
        snap = load_snapshot(args.snapshot)
    else:
        if not args.instance:
            ap.error("--goad needs --instance")
        with tempfile.TemporaryDirectory() as tmp:
            out = args.out or Path(tmp)
            out.mkdir(mode=0o700, parents=True, exist_ok=True)
            print(f"Snapshotting instance {args.instance} (read-only)...", flush=True)
            take_snapshot(lab, plan, args.goad.resolve(), args.instance, out.resolve(), args.ansible_playbook)
            snap = load_snapshot(out)

    results = run_checks(lab, snap, plan, args.phase)
    for phase, _, ok, label, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  P{phase}  {label}" + (f"\n            {detail}" if detail and not ok else ""))
    known = {r["SamAccountName"].lower() for r in lab["rows"]} | {s.lower() for s in lab["domain"]["users"]}
    extra = sorted(u["sam"] for u in snap["dc"]["users"] if u["sam"].lower() not in known)
    print(f"info        {len(snap['dc']['users'])} AD users; not from the generator: {', '.join(extra) or 'none'}")
    failed = sum(not ok for _, _, ok, _, _ in results)
    print(f"\n{f'{failed} of {len(results)} checks FAILED' if failed else f'All {len(results)} checks passed.'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
