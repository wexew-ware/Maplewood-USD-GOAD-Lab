"""Offline tests for verify.py: a synthetic snapshot of a perfect build passes every check, and
targeted breaks fail the right ones. Run: python3 -m unittest discover -s verify/tests"""
import copy
import datetime
import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "verify"))
import verify  # noqa: E402

# Thursday 11:00 Pacific (school hours) and Thursday 21:00 Pacific, in UTC.
SCHOOL_HOURS = datetime.datetime(2026, 10, 22, 19, 0)
EVENING = datetime.datetime(2026, 10, 23, 5, 0)


def perfect_snapshot(lab, plan, now=SCHOOL_HOURS):
    """What snapshot.yml would return from a lab built exactly as lab/MAPLEWOOD/ describes."""
    res = lab["resources"]
    nb = lab["domain"]["netbios_name"]
    base = lab["hosts"][next(k for k, h in lab["hosts"].items() if h["type"] == "dc")]["path"]
    homes = {h["sam"]: h for h in res["home_folders"]}
    dns, users = {}, []
    for r in lab["rows"]:
        dns[r["SamAccountName"]] = f"CN={r['DisplayName'].replace(',', chr(92) + ',')},{r['Path']}"
    for sam, u in lab["domain"]["users"].items():
        dns[sam] = f"CN={u['firstname']} {u['surname']},{u['path']}"

    def user(sam, enabled=True, member_of=(), hours="", expires="", manager=None, spns=(), description="",
             script_path="", **attrs):
        h = homes.get(sam, {})
        return {"sam": sam, "dn": dns.get(sam, f"CN={sam},CN=Users,{base}"), "enabled": enabled, "manager": manager,
                "title": None, "department": None, "office": None, "company": None, "employee_id": None, "mail": None,
                **attrs, "member_of": list(member_of), "logon_hours": hours, "expires": expires, "pw_never_expires": True,
                "home_directory": h.get("directory", ""), "home_drive": h.get("drive", ""),
                "spns": list(spns), "description": description, "script_path": script_path}

    for r in lab["rows"]:
        users.append(user(r["SamAccountName"], r["Enabled"] == "true", [g for g in r["Groups"].split(";") if g],
                          verify.csv_hours(r["LogonHours"]), r["AccountExpires"], dns.get(r["Manager"]),
                          description=r["Description"], script_path=r["ScriptPath"],
                          title=r["Title"] or None, department=r["Department"] or None, office=r["Office"] or None,
                          company=r["Company"] or None, employee_id=r["EmployeeID"] or None, mail=r["Mail"] or None))
    for sam, u in lab["domain"]["users"].items():
        users.append(user(sam, member_of=u.get("groups", []), spns=u.get("spns", []), description=u.get("description", "")))
    users.append(user("Administrator", member_of=["Domain Admins"]))

    parents = {}
    for groups in lab["domain"]["groups"].values():
        for name, spec in groups.items():
            for m in spec.get("members", []):
                parents.setdefault(m, []).append(name)
    scopes = {"global": "Global", "domainlocal": "DomainLocal", "universal": "Universal"}
    groups = [{"name": name, "dn": f"CN={name},{spec['path']}", "scope": scopes[scope], "member_of": parents.get(name, [])}
              for scope, gs in lab["domain"]["groups"].items() for name, spec in gs.items()]
    groups.append({"name": "Domain Admins", "dn": f"CN=Domain Admins,CN=Users,{base}", "scope": "Global", "member_of": []})

    def aces(perms):
        rights = {"full": "FullControl", "modify": "Modify, Synchronize", "read": "ReadAndExecute, Synchronize"}
        return [{"identity": who, "rights": rights[level], "type": "Allow"} for who, level in perms.items()]

    shares = []
    for sh in res["shares"]:
        children = [{"name": h["sam"], "ntfs": aces({"BUILTIN\\Administrators": "full", "NT AUTHORITY\\SYSTEM": "full",
                                                     f"{nb}\\{h['sam']}": "modify"})} for h in res["home_folders"]] if sh.get("home") else []
        shares.append({"name": sh["name"], "path": sh["path"], "enumeration": "AccessBased" if sh.get("home") else "Unrestricted",
                       "access": [{"account": a, "right": r} for a, r in sh["share_access"].items()],
                       "protected": True, "ntfs": aces(sh["ntfs"]), "children": children})
    audit_gpo = next((g for g in res["gpos"] if g.get("audit")), None)
    audit_want = {a["subcategory"]: verify.AUDIT_SETTING_NAMES[a["value"]] for a in audit_gpo["audit"]} if audit_gpo else {}
    members = {k: h for k, h in lab["hosts"].items() if h["type"] != "dc"}
    hosts = {k: {"hostname": h["hostname"].upper(), "domain": lab["domain_name"], "part_of_domain": True, "secure_channel": True,
                 "local_groups": {g: list(ms) for g, ms in h.get("local_groups", {}).items()},
                 "audit_policy": dict(audit_want),
                 "shares": shares if k == res["file_server"]["host"] else []} for k, h in members.items()}

    gpos = []
    for g in res["gpos"]:
        gpos.append({"name": g["name"], "exists": True,
                     "links": [{"target": t, "linked": True, "enabled": True} for t in g["links"]],
                     "registry": [{**r, "value": str(r["value"])} for r in g["registry"]],
                     "drives": [{**d, "sid_ok": True} for d in g.get("drives", [])], "version_ad": 131072, "version_ini": 131072,
                     "user_extensions": "[{00000000-0000-0000-0000-000000000000}{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}]"
                                        "[{5794DAFD-BE60-433F-88A2-1A31939AC01F}{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}]" if g.get("drives") else ""})
    share_by_name = {s["name"]: s for s in res["shares"]}
    return {
        "dc": {"dns_root": lab["domain_name"], "netbios": nb, "utc_now": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
               "ous": [o["dn"] for o in lab["tree"]] + [f"OU=Domain Controllers,{base}"], "users": users, "groups": groups,
               "computers": [{"name": h["hostname"].upper(), "dn": f"CN={h['hostname'].upper()},{h['path']}"} for h in members.values()],
               "fgpps": [{**{k: p[k] for k in ("name", "precedence", "min_length", "complexity", "history", "lockout_threshold", "applies_to")},
                          "max_age_days": p["max_age_days"] or 99999} for p in res["password_policies"]],
               "resultant_policies": {sam: verify.policy_expected(lab, sam) for sam in plan["rsop_sams"]},
               "reset_rights": [{**pair, "can_reset": verify.reset_expected(lab, pair["actor"], pair["target"])} for pair in plan["reset_pairs"]],
               "audit_policy": dict(audit_want),
               "replication_grants": [{"sam": s, "get_changes": True, "get_changes_all": True} for s in plan["repl_sams"]],
               "sysvol_files": [{"path": p, "exists": True,
                                 "sha256": hashlib.sha256((ROOT / "lab" / verify.LAB / "files" / "sysvol"
                                                           / res["logon_script"]["filename"]).read_bytes()).hexdigest()}
                                for p in plan["sysvol_paths"]],
               "adcs": ({"ca_installed": True, "ca": ["MAPLEWOOD-CA"], "template": plan["adcs_template"], "exists": True,
                         "name_flag": 1, "eku": [verify.CLIENT_AUTH_EKU], "enrollment_flag": 0, "ra_signature": 0,
                         "enroll_identities": [f"{nb}\\Domain Users", f"{nb}\\Domain Admins"], "published": True}
                        if plan["adcs_template"] else None),
               "gpos": gpos, "csv_left_on_dc": False},
        "signin": [{"sam": s["sam"], "accepted": verify.signin_expected(s, now)} for s in plan["signins"]],
        "probes": [{"sam": p["sam"], "unc": p["unc"], "op": p["op"], "error": "",
                    "allowed": verify.logon_allowed(p["hours"], now) and verify.expected_access(lab, p["sam"], share_by_name[p["share"]], p["op"])}
                   for p in plan["probes"]],
        "sis": ({"sql_account": f"{lab['domain_name']}\\{plan['sis']['service_account']}", "sql_state": "Running",
                 "db_exists": "yes", "grades_rows": 24, "audit": 1, "web_status": 200} if plan["sis"] else None),
        "hosts": hosts,
        "agents": {k: {"hostname": lab["hosts"][k]["hostname"].upper(),
                       "services": [{"name": name, "present": True, "status": "Running", "start": "Automatic"}
                                    for name in res["elk"]["agents"]]}
                   for k in res["elk"]["log_hosts"]} if res.get("elk") else {},
        "elk": ({"queried": True, "reachable": True, "health": {"status": "green"},
                 "indices": [{"index": "winlogbeat-7.17.6-2026.10.23", "docs.count": "4096"}]}
                if res.get("elk") else None),
    }


class VerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = verify.load_lab(ROOT)
        cls.plan = verify.build_plan(cls.lab)
        cls.snap = perfect_snapshot(cls.lab, cls.plan)

    def failing(self, snap):
        return {name for _, name, ok, _, _ in verify.run_checks(self.lab, snap, self.plan) if not ok}

    def user(self, snap, pred):
        return next(u for u in snap["dc"]["users"] if pred(u))

    def fs_share(self, snap, name):
        return next(s for s in snap["hosts"][self.lab["resources"]["file_server"]["host"]]["shares"] if s["name"] == name)

    # --- whole snapshot ---------------------------------------------------------------------
    def test_perfect_build_passes(self):
        self.assertEqual(self.failing(self.snap), set())

    def test_perfect_build_passes_in_the_evening(self):
        self.assertEqual(self.failing(perfect_snapshot(self.lab, self.plan, EVENING)), set())

    def test_every_check_reports(self):
        reported = {name for _, name, _, _, _ in verify.run_checks(self.lab, self.snap, self.plan)}
        self.assertEqual(reported, {fn.__name__ for _, fn in verify.CHECKS})

    def test_phase_filter(self):
        self.assertEqual(verify.run_checks(self.lab, self.snap, self.plan, max_phase=0), [])
        self.assertEqual({p for p, *_ in verify.run_checks(self.lab, self.snap, self.plan, max_phase=1)}, {1})

    # --- phase 1 breaks ---------------------------------------------------------------------
    def test_user_in_wrong_ou(self):
        snap = copy.deepcopy(self.snap)
        u = self.user(snap, lambda u: ",OU=Grade05," in u["dn"])
        u["dn"] = u["dn"].replace(",OU=Grade05,", ",OU=Grade04,")
        self.assertEqual(self.failing(snap), {"bulk_users", "ou_population"})

    def test_missing_group_membership(self):
        snap = copy.deepcopy(self.snap)
        self.user(snap, lambda u: ",OU=Teachers," in u["dn"])["member_of"] = []
        self.assertEqual(self.failing(snap), {"bulk_users", "groups_exact"})

    def test_extra_nested_group(self):
        snap = copy.deepcopy(self.snap)
        next(g for g in snap["dc"]["groups"] if g["name"] == "SG-Substitutes")["member_of"].append("SG-AllStudents")
        self.assertEqual(self.failing(snap), {"groups_exact"})

    def test_prek_logon_hours_missing(self):
        snap = copy.deepcopy(self.snap)
        self.user(snap, lambda u: ",OU=GradePK," in u["dn"])["logon_hours"] = ""
        self.assertEqual(self.failing(snap), {"bulk_users", "account_restrictions"})

    def test_prek_can_sign_in(self):
        snap = copy.deepcopy(self.snap)
        prek = next(s for s in self.plan["signins"] if "GradePK" in s["kind"])
        next(s for s in snap["signin"] if s["sam"] == prek["sam"])["accepted"] = True
        self.assertEqual(self.failing(snap), {"signins"})

    def test_signin_error_or_missing_result(self):
        snap = copy.deepcopy(self.snap)
        snap["signin"][0] = {"sam": snap["signin"][0]["sam"], "accepted": None, "error": "The LDAP server is unavailable."}
        self.assertEqual(self.failing(snap), {"signins"})
        del snap["signin"][0]
        self.assertEqual(self.failing(snap), {"signins"})

    def test_csv_left_on_dc(self):
        snap = copy.deepcopy(self.snap)
        snap["dc"]["csv_left_on_dc"] = True
        self.assertEqual(self.failing(snap), {"import_cleanup"})

    def test_member_host_problems(self):
        snap = copy.deepcopy(self.snap)
        snap["hosts"]["ws01"]["secure_channel"] = False
        snap["hosts"]["ws01"]["local_groups"] = {}
        self.assertEqual(self.failing(snap), {"member_hosts"})
        del snap["hosts"]["ws01"]
        self.assertEqual(self.failing(snap), {"member_hosts"})

    # --- phase 2 breaks ---------------------------------------------------------------------
    def test_share_permission_drift(self):
        snap = copy.deepcopy(self.snap)
        self.fs_share(snap, "Grade05")["ntfs"].append({"identity": "MAPLEWOOD\\DL-Share-Grade05-R", "rights": "Modify, Synchronize", "type": "Allow"})
        self.assertIn("file_shares", self.failing(snap))
        snap = copy.deepcopy(self.snap)
        self.fs_share(snap, "District")["protected"] = False
        self.assertEqual(self.failing(snap), {"file_shares"})

    def test_open_share_closed(self):
        snap = copy.deepcopy(self.snap)
        share = self.fs_share(snap, "Scans")
        share["access"] = [a for a in share["access"] if a["account"] != "Everyone"]
        self.assertEqual(self.failing(snap), {"file_shares"})

    def test_home_folder_problems(self):
        snap = copy.deepcopy(self.snap)
        self.fs_share(snap, "Home$")["children"].pop(0)
        self.assertEqual(self.failing(snap), {"home_folders"})
        snap = copy.deepcopy(self.snap)
        self.user(snap, lambda u: u["home_drive"])["home_directory"] = ""
        self.assertEqual(self.failing(snap), {"home_folders"})

    def test_password_policy_problems(self):
        snap = copy.deepcopy(self.snap)
        snap["dc"]["fgpps"][2]["lockout_threshold"] = 5
        self.assertEqual(self.failing(snap), {"password_policies"})
        snap = copy.deepcopy(self.snap)
        snap["dc"]["resultant_policies"][self.plan["rsop_sams"][-1]] = ""
        self.assertEqual(self.failing(snap), {"password_policies"})

    def test_student_without_school_hours(self):
        snap = copy.deepcopy(self.snap)
        for u in snap["dc"]["users"]:
            if ",OU=Grade05," in u["dn"]:
                u["logon_hours"] = ""
        self.assertEqual(self.failing(snap), {"bulk_users", "student_logon_hours"})

    def test_helpdesk_overreach(self):
        snap = copy.deepcopy(self.snap)
        pair = next(r for r in snap["dc"]["reset_rights"] if r["actor"] == "kevin.ortiz" and not r["can_reset"])
        pair["can_reset"] = True
        self.assertEqual(self.failing(snap), {"helpdesk_delegation"})

    def test_gpo_problems(self):
        for breakage in [lambda g: g[0]["links"][0].update(enabled=False), lambda g: g[0]["registry"][0].update(value="0"),
                         lambda g: g[1]["drives"].pop(), lambda g: g[1].update(version_ini=65536),
                         lambda g: g[1].update(user_extensions="")]:
            snap = copy.deepcopy(self.snap)
            breakage(snap["dc"]["gpos"])
            self.assertEqual(self.failing(snap), {"group_policy"})

    def test_student_can_write_class_share(self):
        snap = copy.deepcopy(self.snap)
        next(p for p in snap["probes"] if p["op"] == "write" and not p["allowed"])["allowed"] = True
        self.assertEqual(self.failing(snap), {"share_access"})
        snap["probes"] = None
        self.assertEqual(self.failing(snap), {"share_access"})

    # --- phase 3 breaks ---------------------------------------------------------------------
    def test_service_account_spn_missing(self):
        snap = copy.deepcopy(self.snap)
        self.user(snap, lambda u: u["sam"] == "svc-sis")["spns"] = []
        self.assertEqual(self.failing(snap), {"service_accounts"})

    def test_copier_password_not_in_description(self):
        snap = copy.deepcopy(self.snap)
        self.user(snap, lambda u: u["sam"] == "svc-copier")["description"] = "copier"
        self.assertEqual(self.failing(snap), {"service_accounts"})

    def test_dcsync_not_granted(self):
        snap = copy.deepcopy(self.snap)
        snap["dc"]["replication_grants"][0]["get_changes_all"] = False
        self.assertEqual(self.failing(snap), {"dcsync_rights"})

    def test_honey_account_privileged_or_missing(self):
        snap = copy.deepcopy(self.snap)
        self.user(snap, lambda u: u["sam"] == "svc-superadmin")["member_of"] = ["Domain Admins"]
        self.assertEqual(self.failing(snap), {"honey_account"})
        snap = copy.deepcopy(self.snap)
        snap["dc"]["users"] = [u for u in snap["dc"]["users"] if u["sam"] != "svc-superadmin"]
        # A missing honey account is a config.json user, so story_accounts flags it too.
        self.assertIn("honey_account", self.failing(snap))

    def test_honey_account_not_in_signins(self):
        self.assertNotIn("svc-superadmin", {s["sam"] for s in self.plan["signins"]})

    def test_logon_script_wrong_hash(self):
        snap = copy.deepcopy(self.snap)
        snap["dc"]["sysvol_files"][0]["sha256"] = "0" * 64
        self.assertEqual(self.failing(snap), {"logon_script"})

    def test_logon_script_scriptpath_missing(self):
        snap = copy.deepcopy(self.snap)
        next(u for u in snap["dc"]["users"] if u["script_path"])["script_path"] = ""
        self.assertEqual(self.failing(snap), {"logon_script"})

    def test_audit_policy_breaks(self):
        snap = copy.deepcopy(self.snap)
        snap["dc"]["audit_policy"]["Kerberos Service Ticket Operations"] = "No Auditing"
        self.assertEqual(self.failing(snap), {"audit_policy"})
        snap = copy.deepcopy(self.snap)
        snap["hosts"]["srv01"]["audit_policy"] = {}
        self.assertEqual(self.failing(snap), {"audit_policy"})

    def test_adcs_template_breaks(self):
        for mutate in [lambda a: a.update(name_flag=0), lambda a: a.update(eku=[]),
                       lambda a: a.update(enrollment_flag=2), lambda a: a.update(published=False),
                       lambda a: a.update(enroll_identities=["MAPLEWOOD\\Domain Admins"]),
                       lambda a: a.update(ca_installed=False)]:
            snap = copy.deepcopy(self.snap)
            mutate(snap["dc"]["adcs"])
            self.assertEqual(self.failing(snap), {"adcs_template"})

    def test_sis_breaks(self):
        for mutate in [lambda s: s.update(sql_state="Stopped"), lambda s: s.update(db_exists="no"),
                       lambda s: s.update(grades_rows=0), lambda s: s.update(web_status=500),
                       lambda s: s.update(sql_account="NT Service\\MSSQL")]:
            snap = copy.deepcopy(self.snap)
            mutate(snap["sis"])
            self.assertEqual(self.failing(snap), {"sis_server"})
        snap = copy.deepcopy(self.snap)
        snap["sis"] = None
        self.assertEqual(self.failing(snap), {"sis_server"})

    def test_log_agents_break(self):
        # a stopped agent on one host, and the whole collection missing
        snap = copy.deepcopy(self.snap)
        host = next(iter(snap["agents"]))
        next(s for s in snap["agents"][host]["services"] if s["name"] == "winlogbeat")["status"] = "Stopped"
        self.assertEqual(self.failing(snap), {"log_agents"})
        snap = copy.deepcopy(self.snap)
        snap["agents"] = {}
        self.assertEqual(self.failing(snap), {"log_agents"})

    def test_elk_server_breaks(self):
        for mutate in [lambda e: e.update(reachable=False),
                       lambda e: e["health"].update(status="red"),
                       lambda e: e.update(indices=[])]:
            snap = copy.deepcopy(self.snap)
            mutate(snap["elk"])
            self.assertEqual(self.failing(snap), {"elk_server"})
        snap = copy.deepcopy(self.snap)
        snap["elk"] = None
        self.assertEqual(self.failing(snap), {"elk_server"})

    # --- expectations -----------------------------------------------------------------------
    def test_signin_expectations(self):
        by_kind = {s["kind"]: s for s in self.plan["signins"]}
        pick = lambda pred: next(s for k, s in by_kind.items() if pred(k))
        prek, grade3 = pick(lambda k: "GradePK" in k), pick(lambda k: "/Grade03" in k)
        grad_off = pick(lambda k: "Graduated" in k and "disabled" in k)
        grad_on = pick(lambda k: "Graduated" in k and "disabled" not in k)
        self.assertFalse(verify.signin_expected(prek, SCHOOL_HOURS))
        self.assertTrue(verify.signin_expected(grade3, SCHOOL_HOURS))
        self.assertFalse(verify.signin_expected(grade3, EVENING))
        self.assertFalse(verify.signin_expected(grad_off, SCHOOL_HOURS))
        self.assertTrue(verify.signin_expected(grad_on, EVENING))
        story = [s for s in self.plan["signins"] if s["kind"] == "story account"]
        honey = (self.lab["resources"] or {}).get("honey_accounts", [])
        self.assertEqual(len(story), len(self.lab["domain"]["users"]) - len(honey))
        self.assertTrue(all(verify.signin_expected(s, EVENING) for s in story))

    def test_named_subs_refused_once_expired(self):
        subs = [s for s in self.plan["signins"] if s["expires"]]
        expiry = datetime.datetime.fromisoformat(subs[0]["expires"]).replace(hour=12)
        self.assertTrue(subs and all(verify.signin_expected(s, expiry - datetime.timedelta(days=1)) for s in subs))
        self.assertFalse(any(verify.signin_expected(s, expiry) for s in subs))

    def test_helpdesk_expectations(self):
        targets = {t["target"] for t in self.plan["reset_pairs"]}
        can = lambda actor: {t for t in targets if verify.reset_expected(self.lab, actor, t)}
        paths = verify.account_paths(self.lab)
        self.assertTrue(can("kevin.ortiz") and all("OU=Maplewood Elementary" in paths[t.lower()] and ",OU=Students," in paths[t.lower()]
                                                   for t in can("kevin.ortiz")))
        overbroad = can("sam.nguyen")
        self.assertTrue(any("OU=Teachers,OU=Staff,OU=Maplewood Elementary" in paths[t.lower()] for t in overbroad))
        self.assertIn("helen.carter", overbroad)
        self.assertNotIn("adm.marcus.lee", overbroad)

    def test_share_expectations(self):
        shares = {s["name"]: s for s in self.lab["resources"]["shares"]}
        student = next(p["sam"] for p in self.plan["probes"] if p["who"] == "Student")
        self.assertTrue(verify.expected_access(self.lab, student, shares["Grade05"], "read"))
        self.assertFalse(verify.expected_access(self.lab, student, shares["Grade05"], "write"))
        self.assertFalse(verify.expected_access(self.lab, student, shares["Grade06"], "read"))
        self.assertTrue(verify.expected_access(self.lab, student, shares["Scans"], "write"))
        self.assertFalse(verify.logon_allowed(next(p["hours"] for p in self.plan["probes"] if p["who"] == "Student"), EVENING))

    def test_one_resultant_policy_sample_per_policy(self):
        self.assertEqual(sorted(verify.policy_expected(self.lab, s) for s in self.plan["rsop_sams"]),
                         sorted(p["name"] for p in self.lab["resources"]["password_policies"]))


if __name__ == "__main__":
    unittest.main()
