"""Tests for the MapleWood generator. Run: python3 -m unittest discover generator/tests"""
import csv
import io
import json
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "generator"))
import generate  # noqa: E402

LAB = "lab/MAPLEWOOD"
BUILTIN_GROUPS = {"Domain Admins"}


class GeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg = yaml.safe_load((ROOT / "scenario" / "district.yml").read_text())
        cls.files = generate.generate(cls.cfg)
        cls.config = json.loads(cls.files[f"{LAB}/data/config.json"])["lab"]
        cls.domain = cls.config["domains"][cls.cfg["domain"]]
        cls.tree = json.loads(cls.files[f"{LAB}/files/ou_tree.json"])
        cls.users = list(csv.DictReader(io.StringIO(cls.files[f"{LAB}/files/users.csv"])))
        cls.base = ",".join(f"DC={p}" for p in cls.cfg["domain"].split("."))

    def test_deterministic(self):
        self.assertEqual(self.files, generate.generate(self.cfg))

    def test_committed_files_up_to_date(self):
        for rel, content in self.files.items():
            self.assertEqual((ROOT / rel).read_text(), content, f"{rel} is stale; run generator/generate.py")

    def test_ou_tree_parents_first_and_unique(self):
        seen = {self.base}
        for o in self.tree:
            self.assertIn(o["path"], seen, f"{o['dn']} listed before its parent")
            self.assertEqual(o["dn"], f"OU={o['name']},{o['path']}")
            self.assertNotIn(o["dn"], seen, f"duplicate OU {o['dn']}")
            seen.add(o["dn"])

    def test_school_ous_repeat_names(self):
        teachers = [o for o in self.tree if o["name"] == "Teachers"]
        self.assertEqual(len(teachers), len(self.cfg["schools"]))

    def test_counts(self):
        active_students = [u for u in self.users if u["Title"] == "Student" and "Disabled" not in u["Path"]]
        grades = sum(len(s["grades"]) for s in self.cfg["schools"])
        self.assertEqual(len(active_students), grades * self.cfg["students_per_grade"])
        teachers = [u for u in self.users if u["Path"].startswith("OU=Teachers,")]
        self.assertEqual(len(teachers), grades * self.cfg["teachers_per_grade"])
        pool = [u for u in self.users if u["Title"] == "Substitute Teacher (shared)"]
        self.assertEqual(len(pool), self.cfg["substitutes"]["pool"])

    def test_no_logon_grades(self):
        no_logon = [u for u in self.users if u["LogonHours"] == "none"]
        expected = len(self.cfg["no_logon_grades"]) * self.cfg["students_per_grade"]
        self.assertEqual(len(no_logon), expected)
        for u in no_logon:
            self.assertRegex(u["Path"], r"^OU=Grade(PK|K),")

    def test_sams_unique_and_valid(self):
        sams = [u["SamAccountName"] for u in self.users] + list(self.domain["users"])
        self.assertEqual(len(sams), len(set(sams)))
        for s in sams:
            self.assertLessEqual(len(s), 20, s)
            self.assertRegex(s, r"^[a-z0-9.\-]+$")

    def test_paths_exist(self):
        dns = {o["dn"] for o in self.tree}
        for u in self.users:
            self.assertIn(u["Path"], dns, u["SamAccountName"])
        for sam, u in self.domain["users"].items():
            self.assertIn(u["path"], dns, sam)
        for key, h in self.config["hosts"].items():
            if h["type"] != "dc":
                self.assertIn(h["path"], dns, key)
        for name, g in self.domain["groups"]["global"].items():
            self.assertIn(g["path"], dns, name)

    def test_groups_exist(self):
        groups = set(self.domain["groups"]["global"]) | BUILTIN_GROUPS
        for u in self.users:
            for g in filter(None, u["Groups"].split(";")):
                self.assertIn(g, groups, f"{u['SamAccountName']} -> {g}")
        for sam, u in self.domain["users"].items():
            for g in u["groups"]:
                self.assertIn(g, groups, f"{sam} -> {g}")
        for name, g in self.domain["groups"]["global"].items():
            for m in g.get("members", []):
                self.assertIn(m, groups, f"{name} member {m}")

    def test_managers_exist(self):
        accounts = {u["SamAccountName"] for u in self.users} | set(self.domain["users"])
        for u in self.users:
            if u["Manager"]:
                self.assertIn(u["Manager"], accounts, u["SamAccountName"])

    def test_organisation_units_left_to_mw_ou_tree(self):
        self.assertEqual(self.domain["organisation_units"], {})

    def test_student_logon_hours_are_school_hours(self):
        spec, offset = self.cfg["student_logon_hours"], self.cfg["utc_offset"]
        grade5 = next(u for u in self.users if u["Path"].startswith("OU=Grade05,"))
        bits = bytes.fromhex(grade5["LogonHours"])
        allowed = {((i + offset) % 168 // 24, (i + offset) % 24) for i in range(168) if bits[i // 8] >> (i % 8) & 1}
        want = {(generate.DAYS.index(d), h) for d in spec["days"] for h in range(spec["start"], spec["end"])}
        self.assertEqual(allowed, want)
        self.assertNotIn((1, 21), allowed)  # Monday 9pm local
        for u in self.users:
            if u["Title"] == "Student" and ",OU=Disabled," not in u["Path"] and u["LogonHours"] != "none":
                self.assertEqual(u["LogonHours"], grade5["LogonHours"], u["SamAccountName"])

    def test_share_groups_and_acls_reference_real_objects(self):
        groups = {n for scope in self.domain["groups"].values() for n in scope}
        ous = {o["dn"] for o in self.tree}
        for name, spec in self.domain["groups"]["domainlocal"].items():
            self.assertTrue(name.startswith("DL-Share-"), name)
            self.assertTrue(set(spec["members"]) <= groups, name)
        for name, acl in self.domain["acls"].items():
            self.assertIn(acl["for"], groups, name)
            self.assertIn(acl["to"], ous, name)

    def test_resources_reference_real_objects(self):
        res = json.loads(self.files[f"{LAB}/files/resources.json"])
        groups = {n for scope in self.domain["groups"].values() for n in scope} | BUILTIN_GROUPS
        accounts = {u["SamAccountName"] for u in self.users} | set(self.domain["users"])
        ous = {o["dn"] for o in self.tree} | {self.base}
        self.assertIn(res["file_server"]["host"], self.config["hosts"])
        for sh in res["shares"]:
            self.assertTrue(set(sh["groups"]) <= groups, sh["name"])
            if "drive" in sh:
                self.assertIn(sh["drive"]["group"], groups, sh["name"])
        self.assertEqual(sum(bool(sh.get("home")) for sh in res["shares"]), 1)
        for h in res["home_folders"]:
            self.assertIn(h["sam"], accounts)
        for p in res["password_policies"]:
            self.assertTrue(set(p["applies_to"]) <= groups, p["name"])
        self.assertEqual(len({p["precedence"] for p in res["password_policies"]}), len(res["password_policies"]))
        for g in res["gpos"]:
            self.assertTrue(set(g["links"]) <= ous, g["name"])
            for d in g.get("drives", []):
                self.assertIn(d["group"], groups, g["name"])

    def test_sis_mssql_and_iis(self):
        sis = self.cfg["sis"]
        host = self.config["hosts"][sis["host"]]
        self.assertEqual(host["mssql"]["svcaccount"], sis["service_account"])
        self.assertIn("maplegrade_db.ps1", host["scripts"])
        inv = self.files[f"{LAB}/data/inventory"]
        for group in ("mssql", "iis"):
            section = inv.split(f"[{group}]\n", 1)[1].split("\n[", 1)[0]
            self.assertIn(sis["host"], section.split())
        self.assertIn(f"{LAB}/scripts/maplegrade_db.ps1", self.files)
        self.assertIn(sis["sa_password"], self.files[f"{LAB}/scripts/maplegrade_db.ps1"])

    def test_adcs_vulnerable_template(self):
        adcs = self.cfg["adcs"]
        ca = next(h for h in self.cfg["hosts"] if h["key"] == adcs["ca_host"])
        self.assertEqual(self.domain["ca_server"], ca["hostname"])
        inv = self.files[f"{LAB}/data/inventory"]
        self.assertIn(adcs["ca_host"], inv.split("[adcs]\n", 1)[1].split("\n[", 1)[0].split())
        ca_host = self.config["hosts"][adcs["ca_host"]]
        self.assertIn("adcs_templates", ca_host["vulns"])
        self.assertEqual(ca_host["vulns"][0], "files")   # template JSON copied before it is installed
        tmpl = json.loads(self.files[f"{LAB}/files/adcs/{adcs['vulnerable_template']['name']}.json"])
        self.assertEqual(tmpl["msPKI-Certificate-Name-Flag"] & 1, 1)       # ENROLLEE_SUPPLIES_SUBJECT
        self.assertIn("1.3.6.1.5.5.7.3.2", tmpl["pKIExtendedKeyUsage"])     # client authentication
        self.assertEqual(tmpl["msPKI-RA-Signature"], 0)                     # no manager approval

    def test_audit_policy_gpo(self):
        ap = self.cfg["audit_policy"]
        res = json.loads(self.files[f"{LAB}/files/resources.json"])
        gpo = next(g for g in res["gpos"] if g["name"] == ap["gpo_name"])
        self.assertEqual(gpo["links"], [self.base])
        self.assertEqual(len(gpo["audit"]), len(ap["subcategories"]))
        for a in gpo["audit"]:
            self.assertRegex(a["guid"], r"^\{[0-9A-F-]+\}$")
            self.assertIn(a["value"], (0, 1, 2, 3))
        # the GPO also forces advanced audit policy over legacy
        self.assertTrue(any(r["value_name"] == "SCENoApplyLegacyAuditPolicy" for r in gpo["registry"]))

    def test_workstations_not_in_defender_on(self):
        # GOAD's windows_defender role uses win_feature, which fails on client Windows.
        inventory = self.files[f"{LAB}/data/inventory"]
        section = inventory.split("[defender_on]\n", 1)[1].split("\n[", 1)[0]
        workstations = {k for k, h in self.config["hosts"].items() if h["type"] == "workstation"}
        self.assertTrue(workstations)
        self.assertFalse(workstations & set(section.split()))

    def test_service_accounts(self):
        svc_ou = f"OU=Service Accounts,{self.base}"
        for a in self.cfg.get("service_accounts", []):
            u = self.domain["users"][a["sam"]]
            self.assertEqual(u["path"], svc_ou, a["sam"])
            self.assertEqual(u.get("spns", []), a.get("spns", []), a["sam"])
            if a.get("weakness") == "password_in_description":
                self.assertIn(a["password"], u["description"])

    def test_honey_account_has_no_privilege(self):
        for a in self.cfg.get("honey_accounts", []):
            u = self.domain["users"][a["sam"]]
            self.assertFalse(set(u["groups"]) & BUILTIN_GROUPS, a["sam"])
            self.assertTrue(u.get("spns"), a["sam"])  # enumerable bait

    def test_dcsync_account_in_replication_rights(self):
        res = json.loads(self.files[f"{LAB}/files/resources.json"])
        want = [a["sam"] for a in self.cfg.get("service_accounts", []) if a.get("dcsync")]
        self.assertEqual(res["replication_rights"], want)
        for sam in want:
            self.assertIn(sam, self.domain["users"])

    def test_hvac_vendor_rdp(self):
        srv = self.config["hosts"]["srv01"]
        self.assertIn(f"{self.cfg['netbios']}\\svc-hvac", srv["local_groups"]["Remote Desktop Users"])

    def test_standing_local_admins_in_answer_key(self):
        key = self.files["instructor/answer_key.md"]
        for h in self.cfg["hosts"]:
            for sam in h.get("local_groups", {}).get("Administrators", []):
                self.assertIn(f"{self.cfg['netbios']}\\{sam}",
                              self.config["hosts"][h["key"]]["local_groups"]["Administrators"])
                self.assertIn(f"| `{sam}` |", key)

    def test_logon_script_and_scriptpath(self):
        ls = self.cfg["logon_script"]
        script = self.files[f"{LAB}/files/sysvol/{ls['filename']}"]
        embed = next(a for a in self.cfg["service_accounts"] if a["sam"] == ls["embeds"])
        self.assertIn(embed["password"], script)            # credentials in SYSVOL
        staff = {r["SamAccountName"] for r in self.users if r["ScriptPath"]}
        self.assertTrue(staff)
        for r in self.users:
            self.assertEqual(bool(r["ScriptPath"]), r["SamAccountName"] in staff)
            if r["ScriptPath"]:
                self.assertEqual(r["ScriptPath"], ls["filename"])
                self.assertEqual(r["Title"] != "Student", True)
        # the DC places the script into SYSVOL via GOAD's files vuln
        self.assertIn("files", self.config["hosts"]["dc01"]["vulns"])


if __name__ == "__main__":
    unittest.main()
