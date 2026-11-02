#!/usr/bin/env python3
"""Generate the MapleWood USD GOAD lab from scenario/district.yml.

Writes, under lab/MAPLEWOOD/:
  data/config.json                 GOAD lab data: hosts, groups, story accounts
  data/inventory                   GOAD lab inventory
  data/inventory_disable_vagrant   inventory used after the vagrant user is removed
  files/ou_tree.json               full OU DNs, parents first (read by mw_ou_tree)
  files/users.csv                  bulk staff and students (read by mw_bulk_users)
  files/resources.json             shares, home folders, password policies, GPOs (Phase 2 roles)
  providers/virtualbox/Vagrantfile and inventory
and instructor/answer_key.md at the repo root.

Same district.yml + same seed = byte-identical output.
"""
from __future__ import annotations

import argparse
import base64
import csv
import io
import json
import random
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
NAMES = Path(__file__).resolve().parent / "names"
LAB = "MAPLEWOOD"

KID_WORDS = ["tiger", "apple", "puppy", "rocket", "panda", "kitten", "pizza", "dino",
             "sunny", "bunny", "turtle", "robot", "star", "moon", "frog", "bear"]
STRONG_WORDS = ["Cedar", "Harbor", "Summit", "Falcon", "Birch", "River", "Aspen", "Meadow",
                "Willow", "Canyon", "Lantern", "Granite", "Orchard", "Coral", "Prairie", "Glacier",
                "Copper", "Thistle", "Juniper", "Beacon", "Hollow", "Ember", "Quarry", "Tundra"]
SYMBOLS = "!#$%*"

ADMIN_TITLES = ["Assistant Superintendent", "HR Director", "HR Specialist", "Business Manager",
                "Payroll Specialist", "Registrar", "Communications Coordinator", "Curriculum Director"]
FACILITIES_TITLES = ["Facilities Director", "Custodian", "Custodian", "Maintenance Technician",
                     "Custodian", "Maintenance Technician", "Groundskeeper", "HVAC Technician"]
SUPPORT_TITLES = ["Front Office Secretary", "School Nurse", "School Counselor", "Paraprofessional",
                  "Librarian", "Attendance Clerk"]
SECONDARY_SUBJECTS = ["English", "Math", "Science", "Social Studies", "Physical Education",
                      "Art", "Music", "Spanish", "Computer Science", "Special Education"]
FORMER_TITLES = ["Teacher", "Paraprofessional", "Custodian", "HR Specialist", "Front Office Secretary"]

# Advanced audit policy subcategory GUIDs (stable, well-known) and the inclusion-setting values.
AUDIT_SUBCATEGORY_GUIDS = {
    "Logon": "{0CCE9215-69AE-11D9-BED3-505054503030}",
    "Logoff": "{0CCE9216-69AE-11D9-BED3-505054503030}",
    "Special Logon": "{0CCE921B-69AE-11D9-BED3-505054503030}",
    "Credential Validation": "{0CCE923F-69AE-11D9-BED3-505054503030}",
    "Kerberos Authentication Service": "{0CCE9242-69AE-11D9-BED3-505054503030}",
    "Kerberos Service Ticket Operations": "{0CCE9240-69AE-11D9-BED3-505054503030}",
    "User Account Management": "{0CCE9235-69AE-11D9-BED3-505054503030}",
    "Directory Service Access": "{0CCE923B-69AE-11D9-BED3-505054503030}",
    "File Share": "{0CCE9224-69AE-11D9-BED3-505054503030}",
    "Detailed File Share": "{0CCE9244-69AE-11D9-BED3-505054503030}",
    "File System": "{0CCE921D-69AE-11D9-BED3-505054503030}",
    "Process Creation": "{0CCE922B-69AE-11D9-BED3-505054503030}",
}
AUDIT_SETTING_VALUES = {"none": 0, "success": 1, "failure": 2, "both": 3}

CSV_FIELDS = ["SamAccountName", "GivenName", "Surname", "DisplayName", "Path", "Password",
              "Enabled", "Title", "Department", "Office", "Company", "EmployeeID", "Mail",
              "Description", "Manager", "Groups", "AccountExpires", "LogonHours", "ScriptPath"]


# --- small helpers -------------------------------------------------------------

SPECIAL_GRADES = {"PK": (-1, "Pre-K"), "K": (0, "Kindergarten")}


def grade_num(g) -> int:
    return SPECIAL_GRADES[str(g)][0] if str(g) in SPECIAL_GRADES else int(g)


def grade_ou(g) -> str:
    return f"Grade{g}" if str(g) in SPECIAL_GRADES else f"Grade{int(g):02d}"


def grade_label(g) -> str:
    return SPECIAL_GRADES[str(g)][1] if str(g) in SPECIAL_GRADES else f"Grade {int(g)}"


DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]


def logon_hours_hex(days: list[str], start: int, end: int, utc_offset: int) -> str:
    """AD logonHours for local hours [start, end) on the given days: 21 bytes, one bit per UTC
    hour of the week, Sunday 00:00 UTC first, least significant bit first."""
    bits = bytearray(21)
    for d in days:
        for h in range(start, end):
            i = (DAYS.index(d) * 24 + h - utc_offset) % 168
            bits[i // 8] |= 1 << (i % 8)
    return bits.hex()


def clean(s: str) -> str:
    return re.sub(r"[^a-z]", "", s.lower())


def ou(*names: str) -> str:
    """ou("Teachers", "Staff", "Maplewood High") -> 'OU=Teachers,OU=Staff,OU=Maplewood High'"""
    return ",".join(f"OU={n}" for n in names)


class Generator:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.rng = random.Random(cfg["seed"])
        self.base = ",".join(f"DC={p}" for p in cfg["domain"].split("."))
        self.nb = cfg["netbios"]
        self.first_names = (NAMES / "first_names.txt").read_text().split()
        self.last_names = (NAMES / "last_names.txt").read_text().split()
        self.used_sams: set[str] = set()
        self.used_people: set[tuple[str, str]] = set()
        self.next_employee_id = 20100
        self.next_student_id = 104000
        self.schools = {s["code"]: s for s in cfg["schools"]}
        self.rows: list[dict] = []
        self.weak_staff: list[dict] = []
        for a in cfg.get("story_accounts", []):
            self.used_sams.add(a["sam"])
            self.used_people.add((a["first"], a["last"]))

    # --- DNs ---------------------------------------------------------------------
    def dn(self, rel: str) -> str:
        return f"{rel},{self.base}"

    def district_dn(self, child: str | None = None) -> str:
        office = self.cfg["district_office"]["name"]
        return self.dn(ou(child, office) if child else ou(office))

    def school_dn(self, code: str, *children: str) -> str:
        return self.dn(ou(*children, self.schools[code]["name"]))

    # --- OU tree -------------------------------------------------------------------
    def ou_tree(self) -> list[dict]:
        office = self.cfg["district_office"]["name"]
        tree: list[tuple[str, ...]] = [(office,)]
        for child in ["Administration", "Technology", "Facilities", "Substitutes", "Servers"]:
            tree.append((child, office))
        for s in self.cfg["schools"]:
            name = s["name"]
            tree += [(name,), ("Staff", name), ("Teachers", "Staff", name), ("Support Staff", "Staff", name),
                     ("Students", name)]
            tree += [(grade_ou(g), "Students", name) for g in s["grades"]]
            tree += [("Computers", name), ("Staff Workstations", "Computers", name),
                     ("Student Labs", "Computers", name)]
        tree += [("Groups",), ("Service Accounts",), ("Disabled",), ("Graduated", "Disabled"),
                 ("Former Staff", "Disabled")]
        out = []
        for parts in tree:
            parent = self.dn(ou(*parts[1:])) if len(parts) > 1 else self.base
            out.append({"name": parts[0], "path": parent, "dn": self.dn(ou(*parts))})
        return out

    # --- groups --------------------------------------------------------------------
    def groups(self) -> dict:
        gpath = self.dn(ou("Groups"))
        g: dict[str, dict] = {}

        def add(name, members=None):
            g[name] = {"path": gpath}
            if members:
                g[name]["members"] = members

        codes = [s["code"] for s in self.cfg["schools"]]
        for role in ["DistrictAdmin", "Technology", "Facilities", "Substitutes"]:
            add(f"SG-{role}")
        for c in codes:
            add(f"SG-{c}-Teachers")
            add(f"SG-{c}-SupportStaff")
            add(f"SG-{c}-Staff", [f"SG-{c}-Teachers", f"SG-{c}-SupportStaff"])
            add(f"SG-{c}-HelpDesk")
        add("SG-Teachers", [f"SG-{c}-Teachers" for c in codes])
        add("SG-SupportStaff", [f"SG-{c}-SupportStaff" for c in codes])
        add("SG-AllStaff", ["SG-DistrictAdmin", "SG-Technology", "SG-Facilities", "SG-Substitutes"]
            + [f"SG-{c}-Staff" for c in codes])
        for s in self.cfg["schools"]:
            for gr in s["grades"]:
                add(f"SG-{grade_ou(gr)}")
            add(f"SG-{s['code']}-Students", [f"SG-{grade_ou(gr)}" for gr in s["grades"]])
        add("SG-AllStudents", [f"SG-{c}-Students" for c in codes])
        add("SG-SIS-Users", ["SG-Teachers"])
        add("SG-SIS-Admins")
        # AGDLP: the share permission groups are domain local and hold the global groups.
        dl = {name: {"path": gpath, "members": members}
              for share in self.shares() for name, members in share["groups"].items()}
        return {"universal": {}, "global": g, "domainlocal": dl}

    # --- Phase 2: file server, delegation, policies -----------------------------------
    def file_server(self) -> dict:
        fs = self.cfg["file_server"]
        host = next(h for h in self.cfg["hosts"] if h["key"] == fs["host"])
        return {"host": fs["host"], "hostname": host["hostname"], "root": fs["root"]}

    def shares(self) -> list[dict]:
        """Every share on the file server, its permission groups (DL group -> global groups),
        NTFS levels at the share root and, where one is mapped, the drive letter and group."""
        if "file_server" not in self.cfg:
            return []
        fs = self.file_server()
        admins = {"BUILTIN\\Administrators": "full", "NT AUTHORITY\\SYSTEM": "full"}
        out = []

        def add(name, folder, description, modify=(), read=(), drive=None, map_for=None):
            groups, ntfs = {}, dict(admins)
            for level, members, suffix in [("modify", modify, "RW"), ("read", read, "R")]:
                if members:
                    groups[f"DL-Share-{folder}-{suffix}"] = list(members)
                    ntfs[f"{self.nb}\\DL-Share-{folder}-{suffix}"] = level
            share = {"name": name, "path": f"{fs['root']}\\{folder}", "description": description,
                     "share_access": {"BUILTIN\\Administrators": "Full", "NT AUTHORITY\\Authenticated Users": "Change"},
                     "groups": groups, "ntfs": ntfs}
            if drive:
                share["drive"] = {"letter": drive, "group": map_for}
            out.append(share)
            return share

        home = add("Home$", "Home", "Staff home folders (H:)")
        home["home"] = True
        add("District", "District", "District-wide documents", modify=["SG-DistrictAdmin"], read=["SG-AllStaff"],
            drive="P", map_for="SG-AllStaff")
        add("Technology$", "Technology", "Technology department", modify=["SG-Technology"], drive="T", map_for="SG-Technology")
        add("Facilities$", "Facilities", "Facilities department", modify=["SG-Facilities"], drive="F", map_for="SG-Facilities")
        for s in self.cfg["schools"]:
            code = s["code"]
            add(f"{code}-Staff$", f"{code}-Staff", f"{s['name']} staff", modify=[f"SG-{code}-Staff"],
                drive="S", map_for=f"SG-{code}-Staff")
        for s in self.cfg["schools"]:
            for gr in s["grades"]:
                add(grade_ou(gr), grade_ou(gr), f"{grade_label(gr)} class share ({s['name']})",
                    modify=[f"SG-{s['code']}-Teachers"], read=[f"SG-{grade_ou(gr)}"], drive="G", map_for=f"SG-{grade_ou(gr)}")
        open_share = self.cfg["file_server"].get("open_share")
        if open_share:
            o = add(open_share, open_share, "Copier scan drop folder")
            o["ntfs"]["Everyone"] = "full"
            o["share_access"] = {"Everyone": "Full"}
            o["seeded_weakness"] = "open to Everyone"
        return out

    def _is_regular_staff(self, row: dict) -> bool:
        """A real, enabled staff member in the CSV (not a student, shared pool account or disabled one)."""
        return (row["Title"] != "Student" and row["Enabled"] == "true" and bool(row["EmployeeID"])
                and ",OU=Disabled," not in row["Path"])

    def home_folders(self) -> list[dict]:
        """Staff with a home folder: enabled named staff accounts (not shared or disabled ones)
        and the story accounts except separate admin accounts."""
        fs = self.file_server()
        drive = self.cfg["file_server"]["home_drive"]
        sams = [r["SamAccountName"] for r in self.rows if self._is_regular_staff(r)]
        sams += [a["sam"] for a in self.cfg.get("story_accounts", []) if "Domain Admins" not in a.get("groups", [])]
        return [{"sam": sam, "directory": f"\\\\{fs['hostname']}\\Home$\\{sam}", "drive": drive} for sam in sams]

    def logon_script(self) -> dict | None:
        """The SYSVOL logon script: its filename, NETLOGON path, the account whose password it
        embeds, and the staff accounts it is set on. Returns None when not configured."""
        ls = self.cfg.get("logon_script")
        if not ls:
            return None
        fn = ls["filename"]
        return {"filename": fn, "netlogon_path": f"C:\\Windows\\SYSVOL\\domain\\scripts\\{fn}",
                "embeds": ls.get("embeds", ""),
                "accounts": [r["SamAccountName"] for r in self.rows if self._is_regular_staff(r)]}

    def replication_rights(self) -> list[str]:
        """Accounts granted DCSync (DS-Replication-Get-Changes[-All]) on the domain head."""
        return [a["sam"] for a in self.cfg.get("service_accounts", []) if a.get("dcsync")]

    def acls(self) -> dict:
        """Helpdesk delegation for GOAD's acl role: reset password on descendants of an OU."""
        if "helpdesk" not in self.cfg:
            return {}
        acls = {}
        reset = {"right": "Ext-User-Force-Change-Password", "inheritance": "Descendents"}
        for s in self.cfg["schools"]:
            c = s["code"]
            acls[f"ResetPassword_{c}-HelpDesk_{c}-Students"] = {"for": f"SG-{c}-HelpDesk", "to": self.school_dn(c, "Students"), **reset}
        over = self.cfg["helpdesk"].get("overbroad")
        if over:
            for s in self.cfg["schools"]:
                c = s["code"]
                acls[f"ResetPassword_{over}-HelpDesk_{c}-Staff"] = {"for": f"SG-{over}-HelpDesk", "to": self.school_dn(c, "Staff"), **reset}
        return acls

    def password_policies(self) -> list[dict]:
        out = []
        for p in self.cfg.get("password_policies", []):
            applies = list(p.get("applies_to", [])) + [f"SG-{grade_ou(g)}" for g in p.get("applies_to_grades", [])]
            out.append({"name": p["name"], "precedence": p["precedence"], "applies_to": applies,
                        "min_length": p["min_length"], "complexity": p["complexity"], "history": p["history"],
                        "max_age_days": p["max_age_days"], "min_age_days": p.get("min_age_days", 0),
                        "lockout_threshold": p["lockout_threshold"], "lockout_minutes": p.get("lockout_minutes", 30)})
        return out

    def gpos(self) -> list[dict]:
        explorer = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
        system = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
        lockdown = {"name": "MW Student Lockdown", "links": [self.school_dn(s["code"], "Students") for s in self.cfg["schools"]],
                    "registry": [
                        {"key": explorer, "value_name": "NoControlPanel", "type": "DWord", "value": 1},
                        {"key": explorer, "value_name": "NoRun", "type": "DWord", "value": 1},
                        {"key": system, "value_name": "DisableRegistryTools", "type": "DWord", "value": 1},
                        # 2 = no command prompt, but batch files (logon scripts) still run
                        {"key": "HKCU\\Software\\Policies\\Microsoft\\Windows\\System", "value_name": "DisableCMD", "type": "DWord", "value": 2},
                    ]}
        fs = self.file_server()
        drives = [{"letter": sh["drive"]["letter"], "path": f"\\\\{fs['hostname']}\\{sh['name']}", "label": sh["description"],
                   "group": sh["drive"]["group"]} for sh in self.shares() if "drive" in sh]
        maps = {"name": "MW Drive Maps", "links": [self.base], "registry": [], "drives": drives}
        gpos = [lockdown, maps]
        ap = self.cfg.get("audit_policy")
        if ap:
            audit = [{"subcategory": s["name"], "guid": AUDIT_SUBCATEGORY_GUIDS[s["name"]],
                      "value": AUDIT_SETTING_VALUES[s["setting"]]} for s in ap["subcategories"]]
            gpos.append({"name": ap["gpo_name"], "links": [self.base],
                         # Force advanced audit policy to win over any legacy audit settings.
                         "registry": [{"key": "HKLM\\System\\CurrentControlSet\\Control\\Lsa",
                                       "value_name": "SCENoApplyLegacyAuditPolicy", "type": "DWord", "value": 1}],
                         "audit": audit})
        return gpos

    def resources(self) -> dict:
        res = {"file_server": self.file_server(), "shares": self.shares(), "home_folders": self.home_folders(),
               "password_policies": self.password_policies(), "gpos": self.gpos(),
               "student_logon_hours": {**self.cfg["student_logon_hours"], "utc_offset": self.cfg["utc_offset"]},
               "replication_rights": self.replication_rights()}
        ls = self.logon_script()
        if ls:
            res["logon_script"] = ls
        if self.cfg.get("service_accounts"):
            res["service_accounts"] = [{"sam": a["sam"], "weakness": a.get("weakness", ""),
                                        "dcsync": bool(a.get("dcsync"))} for a in self.cfg["service_accounts"]]
        if self.cfg.get("honey_accounts"):
            res["honey_accounts"] = [a["sam"] for a in self.cfg["honey_accounts"]]
        if self.cfg.get("sis"):
            res["sis"] = {"host": self.cfg["sis"]["host"], "db_name": self.cfg["sis"]["db_name"],
                          "service_account": self.cfg["sis"]["service_account"]}
        if self.cfg.get("adcs"):
            res["adcs"] = {"ca_host": self.cfg["adcs"]["ca_host"],
                           "template": self.cfg["adcs"]["vulnerable_template"]["name"]}
        elk = (self.cfg.get("monitoring") or {}).get("elk")
        if elk and elk.get("enabled"):
            res["elk"] = {"ip": elk["ip"],
                          "elasticsearch_port": elk.get("elasticsearch_port", 9200),
                          "kibana_port": elk.get("kibana_port", 5601),
                          "agents": list(elk.get("agents", ["winlogbeat", "sysmon64"])),
                          # elk_log:children = domain, so every domain host runs the log agents
                          "log_hosts": [h["key"] for h in self.cfg["hosts"]]}
        return res

    # --- people --------------------------------------------------------------------
    def person(self) -> tuple[str, str]:
        while True:
            p = (self.rng.choice(self.first_names), self.rng.choice(self.last_names))
            if p not in self.used_people:
                self.used_people.add(p)
                return p

    def unique_sam(self, base: str) -> str:
        base = base[:20]
        sam, n = base, 2
        while sam in self.used_sams:
            suffix = str(n)
            sam = base[:20 - len(suffix)] + suffix
            n += 1
        self.used_sams.add(sam)
        return sam

    def strong_password(self) -> str:
        w1, w2 = self.rng.sample(STRONG_WORDS, 2)
        return f"{w1}{w2}{self.rng.randint(10, 99)}{self.rng.choice(SYMBOLS)}"

    def staff_password(self, row: dict) -> str:
        if self.rng.random() < self.cfg["passwords"]["weak_staff_ratio"]:
            pw = self.rng.choice(self.cfg["passwords"]["weak_staff_list"])
            self.weak_staff.append({"sam": row["SamAccountName"], "title": row["Title"], "password": pw})
            return pw
        return self.strong_password()

    def staff_row(self, first, last, path, title, department, office, groups, manager="",
                  sam_prefix="", expires="", description="", enabled=True, weak_ok=True) -> dict:
        sam = self.unique_sam(f"{sam_prefix}{clean(first)}.{clean(last)}")
        row = {
            "SamAccountName": sam, "GivenName": first, "Surname": last,
            "DisplayName": f"{first} {last}", "Path": path, "Password": "",
            "Enabled": str(enabled).lower(), "Title": title, "Department": department,
            "Office": office, "Company": "MapleWood USD", "EmployeeID": str(self.next_employee_id),
            "Mail": f"{sam}@{self.cfg['mail_domains']['staff']}", "Description": description or title,
            "Manager": manager, "Groups": ";".join(groups), "AccountExpires": expires, "LogonHours": "",
            "ScriptPath": "",
        }
        self.next_employee_id += 1
        row["Password"] = self.staff_password(row) if weak_ok else self.strong_password()
        self.rows.append(row)
        return row

    def student_row(self, first, last, grad_year, grade, school, path, groups, enabled=True,
                    description="") -> dict:
        sid = self.next_student_id
        self.next_student_id += self.rng.randint(1, 9)
        sam = self.unique_sam(f"{grad_year}{clean(first)[0]}{clean(last)}")
        young = str(grade) in [str(x) for x in self.cfg["passwords"]["young_student_grades"]]
        pw = f"{self.rng.choice(KID_WORDS)}{self.rng.randint(10, 99)}" if young else f"Maple{sid}"
        no_logon = str(grade) in [str(x) for x in self.cfg.get("no_logon_grades", [])]
        hours = self.cfg.get("student_logon_hours")
        if no_logon:
            logon_hours = "none"
        elif hours and grade is not None and enabled:
            logon_hours = logon_hours_hex(hours["days"], hours["start"], hours["end"], self.cfg["utc_offset"])
        else:
            logon_hours = ""
        row = {
            "SamAccountName": sam, "GivenName": first, "Surname": last,
            "DisplayName": f"{first} {last}", "Path": path, "Password": pw,
            "Enabled": str(enabled).lower(), "Title": "Student",
            "Department": grade_label(grade) if grade is not None else "",
            "Office": school["name"] if school else "", "Company": "MapleWood USD",
            "EmployeeID": str(sid), "Mail": f"{sam}@{self.cfg['mail_domains']['students']}",
            "Description": description or f"Class of {grad_year}", "Manager": "",
            "Groups": ";".join(groups), "AccountExpires": "", "LogonHours": logon_hours,
            "ScriptPath": "",
        }
        self.rows.append(row)
        return row

    def build_people(self):
        cfg = self.cfg
        story = cfg.get("story_accounts", [])
        counted = [a for a in story if a.get("counted", True)]
        office = cfg["district_office"]["name"]
        superintendent = next((a["sam"] for a in story if a["title"] == "Superintendent"), "")
        tech_director = next((a["sam"] for a in story if a["title"] == "Director of Technology"), "")
        principals = {a["school"]: a["sam"] for a in story if a["role"] == "principal"}

        # District office roles
        n_admin = cfg["district_office"]["administration"] - sum(a["role"] == "administration" for a in counted)
        for i in range(n_admin):
            f, l = self.person()
            self.staff_row(f, l, self.district_dn("Administration"), ADMIN_TITLES[i % len(ADMIN_TITLES)],
                           "District Administration", office, ["SG-DistrictAdmin"], manager=superintendent)
        n_tech = cfg["district_office"]["technology"] - sum(a["role"] == "technology" for a in counted)
        for _ in range(n_tech):
            f, l = self.person()
            self.staff_row(f, l, self.district_dn("Technology"), "Systems Technician", "Technology", office,
                           ["SG-Technology"], manager=tech_director)
        facilities_director = ""
        for i in range(cfg["district_office"]["facilities"]):
            f, l = self.person()
            title = FACILITIES_TITLES[i % len(FACILITIES_TITLES)]
            r = self.staff_row(f, l, self.district_dn("Facilities"), title, "Facilities", office,
                               ["SG-Facilities"], manager=facilities_director or superintendent)
            if i == 0:
                facilities_director = r["SamAccountName"]

        # Substitutes: named (expiring) and a shared pool
        subs = cfg["substitutes"]
        for _ in range(subs["named"]):
            f, l = self.person()
            self.staff_row(f, l, self.district_dn("Substitutes"), "Substitute Teacher", "Substitutes", office,
                           ["SG-Substitutes"], sam_prefix="sub.", expires=str(cfg["term_end"]),
                           description=f"Substitute teacher, term ends {cfg['term_end']}")
        for i in range(1, subs["pool"] + 1):
            sam = self.unique_sam(f"sub{i:02d}")
            self.rows.append({
                "SamAccountName": sam, "GivenName": "Substitute", "Surname": f"{i:02d}",
                "DisplayName": f"Substitute {i:02d}", "Path": self.district_dn("Substitutes"),
                "Password": subs["pool_password"], "Enabled": "true", "Title": "Substitute Teacher (shared)",
                "Department": "Substitutes", "Office": office, "Company": "MapleWood USD", "EmployeeID": "",
                "Mail": f"{sam}@{cfg['mail_domains']['staff']}",
                "Description": "Shared substitute account - ask the front office for the password",
                "Manager": "", "Groups": "SG-Substitutes", "AccountExpires": "", "LogonHours": "",
            })

        # Schools: support staff, teachers, students
        for s in cfg["schools"]:
            code, name = s["code"], s["name"]
            principal = principals.get(code, "")
            n_principals = cfg["per_school"]["principals"] - sum(
                a["role"] == "principal" and a.get("school") == code for a in counted)
            for _ in range(n_principals):
                f, l = self.person()
                self.staff_row(f, l, self.school_dn(code, "Staff"), "Assistant Principal", "Administration",
                               name, [f"SG-{code}-Staff"], manager=superintendent)
            for i in range(cfg["per_school"]["support_staff"]):
                f, l = self.person()
                self.staff_row(f, l, self.school_dn(code, "Support Staff", "Staff"),
                               SUPPORT_TITLES[i % len(SUPPORT_TITLES)], "Student Services", name,
                               [f"SG-{code}-SupportStaff"], manager=principal)
            for g in s["grades"]:
                for t in range(cfg["teachers_per_grade"]):
                    f, l = self.person()
                    if grade_num(g) >= 6:
                        subject = SECONDARY_SUBJECTS[(grade_num(g) * 3 + t) % len(SECONDARY_SUBJECTS)]
                        title, dept = f"{subject} Teacher", f"{grade_label(g)} {subject}"
                    else:
                        title, dept = f"{grade_label(g)} Teacher", grade_label(g)
                    self.staff_row(f, l, self.school_dn(code, "Teachers", "Staff"), title, dept, name,
                                   [f"SG-{code}-Teachers"], manager=principal)
            for g in s["grades"]:
                grad_year = self.cfg["school_year_end"] + 12 - grade_num(g)
                for _ in range(cfg["students_per_grade"]):
                    f, l = self.rng.choice(self.first_names), self.rng.choice(self.last_names)
                    self.student_row(f, l, grad_year, g, s, self.school_dn(code, grade_ou(g), "Students"),
                                     [f"SG-{grade_ou(g)}"])

        # Stale accounts in the Disabled OUs (some left enabled on purpose)
        st = cfg["stale_accounts"]
        last_class = cfg["school_year_end"] - 1
        for i in range(st["graduated_total"]):
            f, l = self.rng.choice(self.first_names), self.rng.choice(self.last_names)
            self.student_row(f, l, last_class, None, None, self.dn(ou("Graduated", "Disabled")), [],
                             enabled=i < st["graduated_enabled"], description=f"Graduated {last_class}")
        for i in range(st["former_staff_total"]):
            f, l = self.person()
            left_enabled = i < st["former_staff_enabled"]
            code = cfg["schools"][i % len(cfg["schools"])]["code"]
            title = FORMER_TITLES[i % len(FORMER_TITLES)]
            groups = [f"SG-{code}-Teachers"] if (left_enabled and title == "Teacher") else (
                [f"SG-{code}-Staff"] if left_enabled else [])
            self.staff_row(f, l, self.dn(ou("Former Staff", "Disabled")), title, "Former Staff",
                           self.schools[code]["name"], groups, enabled=left_enabled,
                           description=f"Left the district June {last_class - 1}")

        # Phase 3: set the SYSVOL logon script on real staff accounts.
        if cfg.get("logon_script"):
            fn = cfg["logon_script"]["filename"]
            for r in self.rows:
                if self._is_regular_staff(r):
                    r["ScriptPath"] = fn

    # --- GOAD config.json ------------------------------------------------------------
    def story_users(self) -> dict:
        users = {}
        for a in self.cfg.get("story_accounts", []):
            if a["role"] == "principal":
                path, groups = self.school_dn(a["school"], "Staff"), [f"SG-{a['school']}-Staff"]
            elif a["role"] == "technology":
                path, groups = self.district_dn("Technology"), ["SG-Technology"]
                if a.get("helpdesk"):
                    groups.append(f"SG-{a['school']}-HelpDesk")
            elif a["role"] == "administration":
                path, groups = self.district_dn("Administration"), ["SG-DistrictAdmin"]
            else:
                raise ValueError(f"unknown story role {a['role']}")
            if "groups" in a:
                groups = list(a["groups"])
            users[a["sam"]] = {
                "firstname": a["first"], "surname": a["last"], "password": a["password"],
                "city": "Maplewood", "description": a["title"], "groups": groups, "path": path,
            }
        # Phase 3: service accounts (in OU=Service Accounts) and the honey account.
        svc_path = self.dn(ou("Service Accounts"))
        for a in self.cfg.get("service_accounts", []):
            entry = {"firstname": a["first"], "surname": a["last"], "password": a["password"],
                     "city": "Maplewood", "description": a["description"], "groups": list(a.get("groups", [])),
                     "path": svc_path}
            if a.get("spns"):
                entry["spns"] = list(a["spns"])
            users[a["sam"]] = entry
        for a in self.cfg.get("honey_accounts", []):
            entry = {"firstname": a["first"], "surname": a["last"], "password": a["password"],
                     "city": "Maplewood", "description": a["description"], "groups": list(a.get("groups", [])),
                     "path": self.district_dn(a["path"]) if a.get("path") else svc_path}
            if a.get("spns"):
                entry["spns"] = list(a["spns"])
            users[a["sam"]] = entry
        return users

    def hosts(self) -> dict:
        out = {}
        for h in self.cfg["hosts"]:
            entry = {
                "hostname": h["hostname"],
                "type": h["type"],
                "local_admin_password": self.cfg["domain_password"] if h["type"] == "dc" else h["local_admin_password"],
                "domain": self.cfg["domain"],
                "path": self.base if h["type"] == "dc" else self.dn(h["ou"]),
                "local_groups": {grp: [f"{self.nb}\\{m}" for m in members]
                                 for grp, members in h.get("local_groups", {}).items()},
                "scripts": [], "vulns": [], "security": [],
            }
            # Phase 3 host extras. "files" (if any) runs first so copied files are in place
            # before the vulns that consume them (e.g. the ADCS template JSON).
            files_vars, vulns, vulns_vars, scripts = {}, [], {}, []
            if h["type"] == "dc" and self.cfg.get("logon_script"):
                fn = self.cfg["logon_script"]["filename"]
                files_vars["logon_script"] = {"src": f"sysvol/{fn}",
                                              "dest": f"C:\\Windows\\SYSVOL\\domain\\scripts\\{fn}"}
            adcs = self.cfg.get("adcs")
            if adcs and h["key"] == adcs["ca_host"]:
                tmpl = adcs["vulnerable_template"]["name"]
                # Stage in C:\Windows\Temp (always present); the files vuln runs before the
                # adcs_templates vuln, which is what creates C:\setup.
                dest = f"C:\\Windows\\Temp\\{tmpl}.json"
                files_vars["adcs_template"] = {"src": f"adcs/{tmpl}.json", "dest": dest}
                vulns.append("adcs_templates")
                vulns_vars["adcs_templates"] = {"wifi": {"template_name": tmpl, "template_file": dest}}
                # New-ADCSTemplate -Publish sets the AD attribute but the CA service needs a reload
                # before it will issue the template; this script does that, idempotently.
                scripts.append("adcs_publish.ps1")
            sis = self.cfg.get("sis")
            if sis and h["key"] == sis["host"]:
                entry["mssql"] = {"sa_password": sis["sa_password"], "svcaccount": sis["service_account"],
                                  "sysadmins": list(sis.get("sysadmins", []))}
                files_vars["maplegrade_web"] = {"src": f"{h['key']}/wwwroot", "dest": "C:\\inetpub\\"}
                scripts.append("maplegrade_db.ps1")
            gcds = self.cfg.get("gcds")
            if gcds and h["key"] == gcds["host"]:
                files_vars["gcds_config"] = {"src": f"{h['key']}/gcds/{gcds['config_file']}",
                                             "dest": f"{gcds['install_path']}\\{gcds['config_file']}"}
            if files_vars:
                vulns = ["files"] + vulns
                vulns_vars = {"files": files_vars, **vulns_vars}
            entry["vulns"], entry["scripts"] = vulns, scripts
            if vulns_vars:
                entry["vulns_vars"] = vulns_vars
            if h["type"] != "dc":
                entry["use_laps"] = False
            out[h["key"]] = entry
        return out

    def config(self) -> dict:
        dc_key = next(h["key"] for h in self.cfg["hosts"] if h["type"] == "dc")
        domain = {
            "dc": dc_key,
            "domain_password": self.cfg["domain_password"],
            "netbios_name": self.nb,
            "trust": "",
            # Empty on purpose: school-based OUs repeat names, so mw_ou_tree creates them from ou_tree.json.
            "organisation_units": {},
            "groups": self.groups(),
            "multi_domain_groups_member": {},
            "acls": self.acls(),
            "users": self.story_users(),
        }
        adcs = self.cfg.get("adcs")
        if adcs:
            # The CA host's short hostname, used by GOAD's adcs role.
            domain["ca_server"] = next(h["hostname"] for h in self.cfg["hosts"] if h["key"] == adcs["ca_host"])
        return {"lab": {"hosts": self.hosts(), "domains": {self.cfg["domain"]: domain}}}


# --- inventories and Vagrantfile ---------------------------------------------------------

def render_inventory(cfg: dict) -> str:
    hosts = cfg["hosts"]
    by_type = lambda t: "\n".join(h["key"] for h in hosts if h["type"] == t)
    all_keys = "\n".join(h["key"] for h in hosts)
    # GOAD's windows_defender role installs the feature with win_feature, which needs
    # Windows Server; client Windows ships Defender on, so workstations stay out.
    defender_keys = "\n".join(h["key"] for h in hosts if h["type"] != "workstation")
    # Phase 3 heavy wave: the SIS host runs IIS + MSSQL; the CA host runs ADCS.
    sis_host = cfg.get("sis", {}).get("host", "")
    adcs_host = cfg.get("adcs", {}).get("ca_host", "")
    return f"""[all:vars]
; domain_name : folder inside ad/
domain_name={LAB}
; administrator user
admin_user=administrator

; GOAD's mssql role hardcodes a SQL 2019 Express installer link that now 404s; use the stable
; go.microsoft.com fwlink for the same installer instead.
download_url_2019=https://go.microsoft.com/fwlink/?linkid=866658

force_dns_server=no
dns_server=x.x.x.x

;dns server forwarder
dns_server_forwarder=1.1.1.1

; winrm connection (windows)
ansible_user=vagrant
ansible_password=vagrant
ansible_connection=winrm
ansible_winrm_server_cert_validation=ignore
ansible_winrm_operation_timeout_sec=400
ansible_winrm_read_timeout_sec=500

; proxy settings (the lab needs internet for some installs)
enable_http_proxy=no
ad_http_proxy=http://x.x.x.x:xxxx
ad_https_proxy=http://x.x.x.x:xxxx

; LAB SCENARIO CONFIGURATION (generated by generator/generate.py) ------------
[domain]
{all_keys}

[dc]
{by_type('dc')}

[server]
{by_type('server')}

[workstation]
{by_type('workstation')}

; MapleWood file server (mw_shares)
[mw_fileserver]
{cfg["file_server"]["host"] if "file_server" in cfg else ""}

[parent_dc]
{by_type('dc')}

[child_dc]

[trust]

; ADCS CA on the DC; the vulnerable template is installed via the adcs_templates vuln on the DC.
[adcs]
{adcs_host}

[adcs_customtemplates]

[iis]
{sis_host}

[mssql]
{sis_host}

[mssql_ssms]

[mssql_reporting]

[webdav]

[elk_server]

[elk_log]

[laps_dc]
[laps_server]
[laps_workstation]

[update]

[no_update]
{all_keys}

; Windows Defender stays on, as in most districts (DC and servers only; clients have it built in)
[defender_on]
{defender_keys}

[defender_off]
"""


def render_inventory_disable_vagrant(cfg: dict) -> str:
    lines = [f"{h['key']} ansible_host={{{{ip_range}}}}.{h['ip']} dns_domain={next(x['key'] for x in cfg['hosts'] if x['type'] == 'dc')} "
             f"dict_key={h['key']} ansible_user=administrator@{cfg['domain']} ansible_password={cfg['domain_password']}"
             for h in cfg["hosts"]]
    keys = "\n".join(h["key"] for h in cfg["hosts"])
    return ("[default]\n; Note: ansible_host *MUST* be an IPv4 address or setting things like DNS\n"
            "; servers will break.\n" + "\n".join(lines) + f"""

[all:vars]
; domain_name : folder inside ad/
domain_name={LAB}

; winrm connection (windows)
ansible_winrm_transport=ntlm
ansible_user=notused
ansible_password=notused
ansible_connection=winrm
ansible_winrm_server_cert_validation=ignore
ansible_winrm_operation_timeout_sec=400
ansible_winrm_read_timeout_sec=500


; LAB SCENARIO CONFIGURATION -----------------------------
[domain]
{keys}
""")


def render_provider_inventory(cfg: dict) -> str:
    dc = next(h["key"] for h in cfg["hosts"] if h["type"] == "dc")
    lines = [f"{h['key']} ansible_host={{{{ip_range}}}}.{h['ip']} dns_domain={dc} dict_key={h['key']}"
             for h in cfg["hosts"]]
    return ("[default]\n; Note: ansible_host *MUST* be an IPv4 address or setting things like DNS\n"
            "; servers will break.\n; " + "-" * 48 + f"\n; {cfg['domain']}\n; " + "-" * 48 + "\n"
            + "\n".join(lines) + "\n")


def render_vagrantfile(cfg: dict) -> str:
    rows = [f'  {{ :name => "{LAB}-{h["key"].upper()}", :ip => "{{{{ip_range}}}}.{h["ip"]}", :box => "{h["box"]}", '
            f':os => "windows", :cpus => {h["cpus"]}, :mem => {h["mem"]}}}' for h in cfg["hosts"]]
    return "boxes = [\n" + ",\n".join(rows) + "\n]\n"


def render_logon_script(gen: Generator, cfg: dict) -> str:
    """The SYSVOL staff logon script. It maps a share with a service account's password in clear
    text - the seeded "credentials in SYSVOL" weakness. LF line endings; cmd runs it fine."""
    ls = cfg["logon_script"]
    fs = gen.file_server()
    m = ls["map"]
    embed = next((a for a in cfg.get("service_accounts", []) if a["sam"] == ls.get("embeds")), None)
    user = f"{cfg['netbios']}\\{embed['sam']}" if embed else ""
    pw = embed["password"] if embed else ""
    return ("@echo off\n"
            "REM MapleWood USD staff logon script - maps the shared scan folder.\n"
            "REM TODO (IT): move these service credentials out of SYSVOL.\n"
            f"net use {m['drive']} \\\\{fs['hostname']}\\{m['share']} /user:{user} {pw} /persistent:no\n")


# ESC1 certificate template (GOAD's ESC1, renamed for the district): client-authentication EKU +
# ENROLLEE_SUPPLIES_SUBJECT + no manager approval. The adcs_templates vuln grants Domain Users enroll.
def render_adcs_template(cfg: dict) -> str:
    name = cfg["adcs"]["vulnerable_template"]["name"]
    tmpl = {
        "name": name, "displayName": name, "objectClass": "pKICertificateTemplate",
        "flags": 131616, "revision": 100,
        "msPKI-Cert-Template-OID": "1.3.6.1.4.1.311.21.8.16735922.7437492.10570883.2539024.15756463.185.9025784.11813641",
        "msPKI-Certificate-Application-Policy": ["1.3.6.1.5.5.7.3.2"],
        "msPKI-Certificate-Name-Flag": 1,          # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (the ESC1 flaw)
        "msPKI-Enrollment-Flag": 0,                 # no manager approval
        "msPKI-Minimal-Key-Size": 2048,
        "msPKI-Private-Key-Flag": 16842752,
        "msPKI-RA-Signature": 0,                    # no authorized signatures required
        "msPKI-Template-Minor-Revision": 4, "msPKI-Template-Schema-Version": 2,
        "pKICriticalExtensions": ["2.5.29.15", "2.5.29.7"],
        "pKIDefaultCSPs": ["3,Microsoft Base DSS Cryptographic Provider",
                           "2,Microsoft Base Cryptographic Provider v1.0",
                           "1,Microsoft Enhanced Cryptographic Provider v1.0"],
        "pKIDefaultKeySpec": 2,
        "pKIExpirationPeriod": [0, 64, 57, 135, 46, 225, 254, 255],
        "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],   # Client Authentication
        "pKIKeyUsage": [128, 0], "pKIMaxIssuingDepth": 0,
        "pKIOverlapPeriod": [0, 128, 166, 10, 255, 222, 255, 255],
    }
    return json.dumps(tmpl, indent=4) + "\n"


def render_maplegrade_web(cfg: dict) -> str:
    title = cfg["sis"].get("web_title", "MapleGrade")
    return (f"<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n<title>{title}</title>\n"
            "<style>body{font-family:Segoe UI,Arial,sans-serif;margin:3rem;color:#1b3a2b}"
            "h1{color:#2f6f4f}.card{max-width:28rem;border:1px solid #cdddd3;border-radius:8px;padding:1.5rem}"
            "label{display:block;margin:.6rem 0 .2rem}input{width:100%;padding:.4rem}</style></head>\n"
            f"<body><h1>{title}</h1>\n<p>Student Information System - staff sign-in</p>\n"
            "<div class=\"card\"><form method=\"post\" action=\"#\">\n"
            "<label>Username</label><input name=\"u\" autocomplete=\"off\">\n"
            "<label>Password</label><input name=\"p\" type=\"password\">\n"
            "<p><button type=\"submit\">Sign in</button></p></form></div>\n"
            "<p style=\"color:#888;margin-top:2rem\">MapleWood USD - lab environment, synthetic data only.</p>\n"
            "</body></html>\n")


def render_adcs_publish(cfg: dict) -> str:
    """Make sure the vulnerable template is published on the CA and the CA service has loaded it
    (New-ADCSTemplate -Publish updates AD, but certsvc only issues it after a reload). Idempotent."""
    name = cfg["adcs"]["vulnerable_template"]["name"]
    return f"""# Ensure {name} is published on the CA and the CA service can issue it.
$ErrorActionPreference = 'Stop'
Import-Module ADCSAdministration
$name = '{name}'
if (((Get-CATemplate | Select-Object -ExpandProperty Name) -notcontains $name)) {{
  Add-CATemplate -Name $name -Force
}}
if ((& certutil -CATemplates 2>$null | Out-String) -notmatch [regex]::Escape($name)) {{
  Restart-Service certsvc -Force
  Start-Sleep 5
}}
exit 0
"""


def render_maplegrade_db(cfg: dict) -> str:
    """Create the MapleGrade database and a Grades table (the grade-change target), via sqlcmd as
    sa. Idempotent; DB/table creation fails loudly, the audit setup is best-effort."""
    sis = cfg["sis"]
    db, sa = sis["db_name"], sis["sa_password"]
    rng = random.Random(cfg["seed"])
    courses = ["Algebra I", "English 9", "Biology", "World History", "Spanish I", "PE", "Art"]
    terms = ["Fall", "Spring"]
    grades = ["A", "A-", "B+", "B", "B-", "C+", "C", "D", "F"]
    students = [f"20{rng.randint(27, 39)}{rng.choice('abcdefghjkmnp')}{rng.choice(['smith','jones','garcia','lee','patel','nguyen','brown'])}"
                for _ in range(12)]
    rows = ",\n  ".join(
        f"('{s}', '{rng.choice(courses)}', '{rng.choice(terms)}', '{rng.choice(grades)}')"
        for s in students for _ in range(2))
    return f"""# MapleGrade SIS database setup (run on the SIS host after MSSQL is installed).
$ErrorActionPreference = 'Stop'
$sa = '{sa}'
$db = '{db}'
function Sql($query, $database) {{
  $d = if ($database) {{ @('-d', $database) }} else {{ @() }}
  & sqlcmd -S localhost -U sa -P $sa -b -l 30 @d -Q $query
  if ($LASTEXITCODE -ne 0) {{ throw "sqlcmd failed ($LASTEXITCODE): $query" }}
}}

# Wait for the SQL service to accept connections (install may have just finished).
for ($i = 0; $i -lt 30; $i++) {{
  try {{ Sql 'SELECT 1'; break }} catch {{ Start-Sleep 10; if ($i -eq 29) {{ throw }} }}
}}

Sql "IF DB_ID('$db') IS NULL CREATE DATABASE [$db];"
Sql "IF OBJECT_ID('dbo.Grades') IS NULL CREATE TABLE dbo.Grades (GradeId INT IDENTITY PRIMARY KEY, StudentSam NVARCHAR(32) NOT NULL, Course NVARCHAR(64) NOT NULL, Term NVARCHAR(16) NOT NULL, Grade NVARCHAR(2) NOT NULL, UpdatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME());" $db
Sql "IF NOT EXISTS (SELECT 1 FROM dbo.Grades) INSERT INTO dbo.Grades (StudentSam, Course, Term, Grade) VALUES
  {rows};" $db

# Best-effort: audit UPDATEs to the Grades table (the grade-change detection), to the app log.
try {{
  Sql "IF NOT EXISTS (SELECT 1 FROM sys.server_audits WHERE name='MapleGrade_Audit') BEGIN CREATE SERVER AUDIT MapleGrade_Audit TO APPLICATION_LOG; ALTER SERVER AUDIT MapleGrade_Audit WITH (STATE = ON); END"
  Sql "IF NOT EXISTS (SELECT 1 FROM sys.database_audit_specifications WHERE name='MapleGrade_GradesAudit') CREATE DATABASE AUDIT SPECIFICATION MapleGrade_GradesAudit FOR SERVER AUDIT MapleGrade_Audit ADD (UPDATE, DELETE ON dbo.Grades BY public) WITH (STATE = ON);" $db
}} catch {{ Write-Warning "grade audit not configured: $_" }}

Write-Host "MapleGrade database ready."
exit 0
"""


def render_gcds_config(cfg: dict) -> str:
    """GCDS config XML on the file server — stores the AD sync account's password (base64)."""
    gcds = cfg["gcds"]
    svc = next(a for a in cfg["service_accounts"] if a["sam"] == gcds["service_account"])
    pw_b64 = base64.b64encode(svc["password"].encode()).decode()
    dc = next(h for h in cfg["hosts"] if h["type"] == "dc")
    base_dn = ",".join(f"DC={p}" for p in cfg["domain"].split("."))
    mail_domain = cfg["mail_domains"]["staff"]
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<!-- Google Cloud Directory Sync — MapleWood USD\n"
        "     Syncs staff and student accounts to Google Workspace nightly.\n"
        "     Contact: marcus.lee (Director of Technology) -->\n"
        "<config>\n"
        "  <general>\n"
        "    <simulationMode>false</simulationMode>\n"
        "    <logLevel>INFO</logLevel>\n"
        "    <maxExceptions>25</maxExceptions>\n"
        "  </general>\n"
        "  <ldap>\n"
        f"    <hostname>{dc['hostname']}.{cfg['domain']}</hostname>\n"
        "    <port>389</port>\n"
        "    <authType>SIMPLE</authType>\n"
        f"    <user>{cfg['netbios']}\\{svc['sam']}</user>\n"
        f'    <password encoding="base64">{pw_b64}</password>\n'
        f"    <baseDN>{base_dn}</baseDN>\n"
        "    <searchScope>SUBTREE</searchScope>\n"
        "  </ldap>\n"
        "  <google>\n"
        f"    <domain>{mail_domain}</domain>\n"
        f"    <adminEmail>it-sync@{mail_domain}</adminEmail>\n"
        "  </google>\n"
        "  <sync>\n"
        "    <users>\n"
        "      <enabled>true</enabled>\n"
        "      <userSearchFilter>(&amp;(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))</userSearchFilter>\n"
        "    </users>\n"
        "    <groups>\n"
        "      <enabled>true</enabled>\n"
        "      <groupSearchFilter>(objectClass=group)</groupSearchFilter>\n"
        "    </groups>\n"
        "  </sync>\n"
        "</config>\n"
    )


def render_lessons(gen: Generator, cfg: dict) -> dict[str, str]:
    """One blue-team lesson per seeded scenario, as Markdown under lessons/. Every lesson names the
    actual accounts/hosts/events for this seed, so instructors can run the attack, find it, fix it."""
    rows = gen.rows
    svc = {a["sam"]: a for a in cfg.get("service_accounts", [])}
    honey = (cfg.get("honey_accounts") or [{}])[0].get("sam", "svc-superadmin")
    fs = gen.file_server()["hostname"]
    over = cfg.get("helpdesk", {}).get("overbroad", "MHS")
    # A young-password student who can actually sign in (grades with simple passwords, minus no-logon grades).
    no_logon = {str(g) for g in cfg.get("no_logon_grades", [])}
    young_grades = [str(g) for g in cfg["passwords"]["young_student_grades"] if str(g) not in no_logon]
    young = next((r for r in rows if r["Title"] == "Student" and r["LogonHours"] not in ("", "none")
                  and any(f"OU={grade_ou(g)}," in r["Path"] for g in young_grades)), rows[0])
    teacher = next(r for r in rows if "OU=Teachers," in r["Path"] and r["Enabled"] == "true")
    weak = gen.weak_staff[0] if gen.weak_staff else {"sam": "(see answer key)", "password": "..."}
    stale = next((r for r in rows if ",OU=Disabled," in r["Path"] and r["Enabled"] == "true"), rows[0])
    f = {
        "fs": fs, "sub_pool": f"sub01-sub{cfg['substitutes']['pool']:02d}", "sub_pw": cfg['substitutes']['pool_password'],
        "term_end": cfg["term_end"], "young": young["SamAccountName"], "young_grade": young["Department"],
        "teacher": teacher["SamAccountName"], "weak": weak["sam"], "weak_pw": weak["password"],
        "stale": stale["SamAccountName"], "stale_ou": re.split(r"(?<!\\),", stale["Path"], maxsplit=1)[0][3:],
        "svc_sis": "svc-sis", "svc_gsync": "svc-gsync", "svc_copier": "svc-copier", "honey": honey,
        "over_hd": f"SG-{over}-HelpDesk", "open_share": cfg.get("file_server", {}).get("open_share", "Scans"),
        "sis_db": cfg.get("sis", {}).get("db_name", "MapleGrade"), "nb": cfg["netbios"],
    }

    def lesson(num, slug, title, seeded, attack, events, hunt, fix, answer):
        ev = "\n".join(f"| {eid} | {desc} |" for eid, desc in events)
        return (f"# {num}. {title}\n\n"
                f"**Seeded weakness.** {seeded}\n\n"
                f"**What the attack looks like.** {attack}\n\n"
                f"## Detect\n\nKey events (Windows Security log, shipped to Kibana by Winlogbeat):\n\n"
                f"| Event | Meaning |\n| --- | --- |\n{ev}\n\n"
                f"**Hunt.** {hunt}\n\n"
                f"## Respond and fix\n\n{fix}\n\n"
                f"## Answer key (instructors)\n\n{answer}\n")

    L = {}
    L["lessons/01-student-password-spray.md"] = lesson(
        "01", "student-password-spray", "Student password spray",
        f"Young students (grades {', '.join(map(str, cfg['passwords']['young_student_grades']))}) get short, "
        f"guessable passwords (a word + 2 digits) and the young-student policy has no lockout.",
        "One or two common passwords are tried against many student accounts from a single host in a short window.",
        [("4625", "Failed logon, type 3 (sub-status 0xC000006A = bad password) - one per sprayed account"),
         ("4776", "The DC validated and rejected the NTLM credentials - one per attempt (the key NTLM signal on a DC)"),
         ("4771 / 4768", "Kerberos spray: 4771 code 0x18 (bad password) during permitted hours; outside student logon hours you get 4768 failures code 0x12 (logon-hours/revoked) instead")],
        f"Group 4625/4776 (and 4771 for a Kerberos spray) by source host over 5-minute windows; a spray is one source failing against **many distinct** "
        f"student accounts across the young-grade groups. Compare the distinct-target count to a normal user's typo rate.",
        "Raise the student password policy (length, and a lockout threshold for the young-student FGPP); reset predictable "
        "passwords; alert on N+ distinct failed targets from one source.",
        f"Sample target: `{f['young']}` ({f['young_grade']}). Pattern: a word from the kid-word list + 2 digits "
        f"(see `instructor/answer_key.md`).")
    L["lessons/02-grade-change.md"] = lesson(
        "02", "grade-change", "Grade change in the SIS",
        f"Weak staff passwords plus the MapleGrade SIS (`{f['sis_db']}` on {f['fs']}). A phished teacher can edit grades.",
        f"A teacher account signs in from an unusual host, then UPDATEs rows in `dbo.Grades`.",
        [("4624", "Successful logon (type 3) - watch for a teacher from an unusual host"),
         ("33205", "SQL Server Audit `MapleGrade_Audit` in the **Application** log (provider `MSSQL$SQLEXPRESS`) - action_id `UP`/`DL` on `dbo.Grades`, with `client_ip`")],
        f"Correlate a teacher logon (e.g. `{f['teacher']}`) from a new host with event **33205** on {f['fs']} (Application channel) showing "
        f"`action_id` UP/DL against `dbo.Grades`. The audit writes to the Windows Application log on {f['fs']}; `client_ip` names the source.",
        "Enforce MFA/stronger staff passwords; restrict SIS write access; review the grade audit trail; alert on grade "
        "UPDATEs outside the registrar's normal hosts.",
        f"Weak staff login to try: `{f['weak']}` / `{f['weak_pw']}`. Audit: `MapleGrade_Audit` -> Application log on {f['fs']}.")
    L["lessons/03-kerberoast-sis.md"] = lesson(
        "03", "kerberoast-sis", "Kerberoasting the SIS service account",
        f"`{f['svc_sis']}` runs MapleGrade and has an SPN, but a weak, crackable password.",
        f"Any domain user requests a service ticket for `{f['svc_sis']}` and cracks it offline.",
        [("4769", "Kerberos service ticket requested - encryption type 0x17 (RC4) is the tell"),
         ("4768", "Kerberos TGT requested (the requesting user)")],
        f"Hunt 4769 where **Ticket Encryption Type = 0x17** and Service Name = `{f['svc_sis']}`, especially from a user "
        f"workstation. One user requesting many service SPNs is roasting at scale.",
        f"Give service accounts long random passwords (or a gMSA); flag RC4 service-ticket requests; limit which accounts "
        f"carry SPNs.",
        f"Target: `{f['svc_sis']}` (SPNs MSSQLSvc/{f['fs']}.* and HTTP/maplegrade.*). Password in `instructor/answer_key.md`.")
    L["lessons/04-helpdesk-overreach.md"] = lesson(
        "04", "helpdesk-overreach", "Helpdesk delegation overreach",
        f"Each school helpdesk may reset its own students, but `{f['over_hd']}` can also reset **staff** in every school.",
        f"A member of `{f['over_hd']}` resets a staff/admin password, then signs in as them.",
        [("4724", "An attempt was made to reset an account's password"),
         ("4738", "A user account was changed")],
        f"Alert on 4724 where the **target** is outside a `Students` OU (i.e. a staff/admin account) and the **subject** is a "
        f"helpdesk account. Legitimate helpdesk resets target students only.",
        f"Scope each helpdesk's reset delegation to its own `Students` OU; remove the cross-school staff delegation on "
        f"`{f['over_hd']}`.",
        f"Over-broad group: `{f['over_hd']}`. Members and a sample staff target are in `instructor/answer_key.md`.")
    L["lessons/05-shared-substitute.md"] = lesson(
        "05", "shared-substitute", "Shared / expired substitute accounts",
        f"A shared substitute pool (`{f['sub_pool']}`) with one password, and named subs that expire on {f['term_end']}.",
        f"A shared sub account is used after hours or after the term ends; nobody can say who used it.",
        [("4624", "Successful logon - a `sub0x` logon outside school hours"),
         ("4625", "Failed logon - status 0xC0000193 means the account has expired")],
        f"Flag any 4624 for `{f['sub_pool']}` outside school hours, and 4625 with **status 0xC0000193** (expired) after "
        f"{f['term_end']}. Shared accounts have no individual accountability - treat every use as notable.",
        "Replace shared subs with per-person accounts; set and enforce expiry; disable the pool out of term.",
        f"Shared pool: `{f['sub_pool']}`, password `{f['sub_pw']}`. Named subs expire {f['term_end']}.")
    L["lessons/06-sysvol-credentials.md"] = lesson(
        "06", "sysvol-credentials", "Credentials in a SYSVOL logon script",
        f"The staff logon script (`\\\\{cfg['domain']}\\NETLOGON\\{cfg.get('logon_script', {}).get('filename', 'logon.bat')}`) "
        f"maps a share using `{f['svc_copier']}`'s password in clear text.",
        f"An attacker reads the logon script from NETLOGON and harvests the hardcoded `{f['svc_copier']}` password.",
        [("5145", "Detailed File Share: the read of NETLOGON\\logon.bat (reliable - needs no SACL; the client IP is in `event_data.IpAddress`, not `source.ip`)"),
         ("4663", "Object access on the file - only if a SACL is set (SYSVOL has none by default); otherwise rely on 5145")],
        f"Baseline who reads the logon script (every staff logon does). Hunt 5145 for `logon.bat` from **unexpected hosts** "
        f"(filter on `winlog.event_data.IpAddress`) or accounts that never log on interactively.",
        f"Remove credentials from SYSVOL; rotate `{f['svc_copier']}`'s password; map shares by GPP with no stored creds.",
        f"Script embeds `{f['svc_copier']}`'s password (see `instructor/answer_key.md`).")
    L["lessons/07-stale-account-reuse.md"] = lesson(
        "07", "stale-account-reuse", "Stale account reuse",
        "Some graduated students and former staff were left enabled in the `Disabled` OUs.",
        "A long-untouched account (a graduate or ex-employee) suddenly authenticates.",
        [("4624", "Successful logon for an account under OU=Disabled"),
         ("4768", "Kerberos TGT requested for such an account")],
        f"Alert on any 4624/4768 for accounts whose DN is under `OU=Graduated` or `OU=Former Staff`. These should never log "
        f"on - any authentication is suspicious.",
        "Disable (don't just move) departed accounts; review enabled accounts in the Disabled OUs; alert on any use.",
        f"Sample enabled stale account: `{f['stale']}` (in `{f['stale_ou']}`).")
    L["lessons/08-dcsync-sync-account.md"] = lesson(
        "08", "dcsync-sync-account", "Directory-sync account abuse (DCSync)",
        f"`{f['svc_gsync']}` (a directory-sync account) was granted replication rights on the domain - it can DCSync.",
        f"`{f['svc_gsync']}` (or anyone who compromises it) replicates password hashes from the DC.",
        [("4662", "An operation was performed on an object - replication extended rights (DS-Replication-Get-Changes `1131f6aa` / -Get-Changes-All `1131f6ad`)"),
         ("4624", "The logon that preceded the replication request")],
        f"Hunt 4662 referencing the replication GUIDs (`1131f6aa`/`1131f6ad`) where the requester is **not a domain controller** - "
        f"e.g. `{f['svc_gsync']}` from a member host. DCs replicate constantly; non-DCs should not.",
        f"Remove replication rights from `{f['svc_gsync']}`; use a least-privilege sync method; alert on non-DC 4662 "
        f"replication.",
        f"Account with DCSync: `{f['svc_gsync']}` (Get-Changes + Get-Changes-All on the domain head).")
    L["lessons/09-share-ransomware.md"] = lesson(
        "09", "share-ransomware", "Share ransomware drill",
        f"Class shares hold student work, and the `{f['open_share']}` share is open to Everyone - a ransomware blast radius.",
        f"One account mass-renames/encrypts files across a class share or the open `{f['open_share']}` share.",
        [("5145", "Detailed File Share: a burst of per-file writes/renames/deletes (reliable - needs no SACL; the client IP is in `event_data.IpAddress`, not `source.ip`)"),
         ("4663", "Object access on the files - only with a SACL on the share (none by default); otherwise rely on 5145")],
        f"Watch for a spike in 5145/4663 **write and delete** events from a single account (or `winlog.event_data.IpAddress`) over a short window on {f['fs']} "
        f"shares. A user touching hundreds of files a minute is not normal.",
        f"Lock down the open `{f['open_share']}` share; least-privilege share/NTFS; backups + canary files; rate-based alerts.",
        f"Open share: `\\\\{f['fs']}\\{f['open_share']}` (Everyone). Class shares per grade.")
    L["lessons/10-honey-account.md"] = lesson(
        "10", "honey-account", "Honey account touched",
        f"`{f['honey']}` looks like a privileged superintendent admin but grants nothing - a tripwire.",
        f"An attacker enumerating or spraying the domain tries to use `{f['honey']}`.",
        [("4771", "Kerberos pre-auth failed for the decoy - a guess/spray against it (status 0x18)"),
         ("4625 / 4776", "Failed NTLM logon and DC credential-validation failure for the decoy"),
         ("4769", "A service ticket requested for the decoy's SPN (roasting) - highest-signal"),
         ("4768 / 4624", "TGT or logon success - only if someone holds the decoy's password (rare, highest severity)")],
        f"Alert on **any** 4624/4625/4768/4769/4771/4776 referencing `{f['honey']}`. No legitimate process uses it, so every hit is "
        f"high-signal. This is the cheapest, highest-fidelity detection in the lab.",
        "Keep the decoy enabled but unused; wire its events straight to a high-priority alert; never log in as it.",
        f"Honey account: `{f['honey']}` (do not use; any auth = alert).")

    scenarios = [(k, v) for k, v in sorted(L.items())]
    index = ("# MapleWood USD - blue-team lessons\n\n"
             "One lesson per seeded weakness: run the attack, find it in the logs, fix it. All events ship to Kibana "
             "via Winlogbeat (Phase 4 ELK). Account names below are for this lab's seed; see `instructor/answer_key.md` "
             "for passwords.\n\n| # | Lesson | Primary events |\n| --- | --- | --- |\n")
    titles = [("01", "Student password spray", "4625 / 4776 (4771 Kerberos)"), ("02", "Grade change in the SIS", "4624 + 33205 (SQL audit)"),
              ("03", "Kerberoasting the SIS service account", "4769 (RC4 0x17)"),
              ("04", "Helpdesk delegation overreach", "4724"), ("05", "Shared / expired substitute accounts", "4624 / 4625 (0xC0000193)"),
              ("06", "Credentials in a SYSVOL logon script", "5145"), ("07", "Stale account reuse", "4624 / 4768"),
              ("08", "Directory-sync account abuse (DCSync)", "4662"), ("09", "Share ransomware drill", "5145"),
              ("10", "Honey account touched", "4769 / 4771 / 4625")]
    # README lives inside lessons/, so link by basename.
    slugs = {k.split("/")[1][:2]: k.split("/")[1] for k, _ in scenarios}
    index += "\n".join(f"| {n} | [{t}]({slugs[n]}) | {e} |" for n, t, e in titles) + "\n"
    L["lessons/README.md"] = index
    return L


def render_answer_key(gen: Generator, cfg: dict) -> str:
    rows = gen.rows
    enabled_stale = [r for r in rows if "Disabled" in r["Path"] and r["Enabled"] == "true"]
    out = io.StringIO()
    out.write("# MapleWood USD answer key (instructors only)\n\n")
    out.write(f"Generated from `scenario/district.yml` with seed {cfg['seed']}. Do not hand this to learners.\n\n")
    out.write("## Weak staff passwords\n\n| Account | Title | Password |\n| --- | --- | --- |\n")
    for w in gen.weak_staff:
        out.write(f"| `{w['sam']}` | {w['title']} | `{w['password']}` |\n")
    out.write("\n## Stale accounts left enabled\n\n| Account | Description | Groups |\n| --- | --- | --- |\n")
    for r in enabled_stale:
        out.write(f"| `{r['SamAccountName']}` | {r['Description']} | {r['Groups'] or '-'} |\n")
    out.write(f"\n## Shared substitute pool\n\n`sub01`-`sub{cfg['substitutes']['pool']:02d}` all use "
              f"`{cfg['substitutes']['pool_password']}`.\n")
    out.write("\n## Student password patterns\n\n"
              f"- {', '.join(map(str, cfg['passwords']['young_student_grades']))}: a short word + 2 digits (e.g. `tiger12`)\n"
              "- Grade 3 and up: `Maple` + student ID (the EmployeeID attribute)\n"
              f"- {', '.join(map(str, cfg.get('no_logon_grades', [])))}: accounts have no permitted logon hours\n")
    if "file_server" in cfg:
        res = gen.resources()
        hours = cfg["student_logon_hours"]
        over = cfg.get("helpdesk", {}).get("overbroad")
        out.write("\n## Phase 2 seeded weaknesses\n\n")
        for sh in res["shares"]:
            if sh.get("seeded_weakness"):
                out.write(f"- `\\\\{res['file_server']['hostname']}\\{sh['name']}` is {sh['seeded_weakness']} (share and NTFS)\n")
        if over:
            out.write(f"- `SG-{over}-HelpDesk` can reset passwords in every school's `Staff` OU, not just its own students\n")
        for p in res["password_policies"]:
            if not p["complexity"] or p["lockout_threshold"] == 0:
                lockout = "no lockout" if p["lockout_threshold"] == 0 else f"lockout after {p['lockout_threshold']}"
                out.write(f"- `{p['name']}` ({', '.join(p['applies_to'])}): minimum length {p['min_length']}, "
                          f"complexity {'on' if p['complexity'] else 'off'}, {lockout}\n")
        out.write(f"- Students may sign in {'/'.join(hours['days'])} {hours['start']:02d}:00-{hours['end']:02d}:00 "
                  f"local time (UTC{cfg['utc_offset']:+d}); anything outside that is an anomaly\n")
    svcs = cfg.get("service_accounts", [])
    honey = cfg.get("honey_accounts", [])
    if svcs or honey:
        out.write("\n## Phase 3 service accounts and seeded weaknesses\n\n")
        out.write("| Account | Password | Weakness |\n| --- | --- | --- |\n")
        notes = {"kerberoast": "Kerberoastable (SPN + weak password); crack offline",
                 "password_in_description": "password is in the account's Description field",
                 "vendor_rdp": "third-party vendor, never expires, allowed to RDP to the server"}
        for a in svcs:
            w = "DCSync (replication rights on the domain)" if a.get("dcsync") else notes.get(a.get("weakness"), "service account")
            out.write(f"| `{a['sam']}` | `{a['password']}` | {w} |\n")
        for a in honey:
            out.write(f"| `{a['sam']}` | `{a['password']}` | honey account - any logon or Kerberos request should alert |\n")
        if cfg.get("logon_script"):
            ls = cfg["logon_script"]
            embed = next((a for a in svcs if a["sam"] == ls.get("embeds")), None)
            out.write(f"\nSYSVOL logon script `scripts\\{ls['filename']}` embeds "
                      f"`{embed['sam']}`'s password in clear text.\n" if embed else "")
        gcds = cfg.get("gcds")
        if gcds:
            gsvc = next((a for a in svcs if a["sam"] == gcds["service_account"]), None)
            if gsvc:
                out.write(f"\nGCDS config on {gcds['host']} (`{gcds['install_path']}\\{gcds['config_file']}`) "
                          f"stores `{gsvc['sam']}`'s password (base64-encoded).\n")
    admins = [(h["hostname"], sam) for h in cfg["hosts"] if h["type"] != "dc"
              for sam in h.get("local_groups", {}).get("Administrators", [])]
    if admins:
        by_sam = {r["SamAccountName"]: r for r in rows}
        out.write("\n## Standing local admins\n\n| Account | Title | Password | Local admin on |\n"
                  "| --- | --- | --- | --- |\n")
        for host, sam in admins:
            r = by_sam.get(sam, {})
            out.write(f"| `{sam}` | {r.get('Title', '-')} | `{r.get('Password', '-')}` | `{host}` |\n")
        out.write("\nStaff who are standing local admins on their own laptop: phish the password and the attacker "
                  "has admin on that host, a pivot into the flat network. The workstation blocks inbound SMB, so "
                  "the admin path is WinRM (5985) or RDP. Fix: remove standing local admin and manage the local "
                  "Administrator password with LAPS.\n")
    return out.getvalue()


# --- main ---------------------------------------------------------------------------------

def generate(cfg: dict) -> dict[str, str]:
    """Return {relative path: file content} for every generated file."""
    gen = Generator(cfg)
    tree = gen.ou_tree()
    gen.build_people()
    config = gen.config()

    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, lineterminator="\n")
    w.writeheader()
    w.writerows(gen.rows)

    lab = f"lab/{LAB}"
    files = {
        f"{lab}/data/config.json": json.dumps(config, indent=2) + "\n",
        f"{lab}/data/inventory": render_inventory(cfg),
        f"{lab}/data/inventory_disable_vagrant": render_inventory_disable_vagrant(cfg),
        f"{lab}/files/ou_tree.json": json.dumps(tree, indent=2) + "\n",
        f"{lab}/files/users.csv": buf.getvalue(),
        f"{lab}/files/resources.json": json.dumps(gen.resources(), indent=2) + "\n",
        f"{lab}/providers/virtualbox/Vagrantfile": render_vagrantfile(cfg),
        f"{lab}/providers/virtualbox/inventory": render_provider_inventory(cfg),
        "instructor/answer_key.md": render_answer_key(gen, cfg),
    }
    if cfg.get("logon_script"):
        files[f"{lab}/files/sysvol/{cfg['logon_script']['filename']}"] = render_logon_script(gen, cfg)
    if cfg.get("adcs"):
        files[f"{lab}/files/adcs/{cfg['adcs']['vulnerable_template']['name']}.json"] = render_adcs_template(cfg)
        files[f"{lab}/scripts/adcs_publish.ps1"] = render_adcs_publish(cfg)
    if cfg.get("sis"):
        files[f"{lab}/files/{cfg['sis']['host']}/wwwroot/index.html"] = render_maplegrade_web(cfg)
        files[f"{lab}/scripts/maplegrade_db.ps1"] = render_maplegrade_db(cfg)
    if cfg.get("gcds"):
        gcds = cfg["gcds"]
        files[f"{lab}/files/{gcds['host']}/gcds/{gcds['config_file']}"] = render_gcds_config(cfg)
    files.update(render_lessons(gen, cfg))
    return files


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", default=ROOT / "scenario" / "district.yml", type=Path)
    ap.add_argument("--out", default=ROOT, type=Path, help="repo root to write into (default: this repo)")
    ap.add_argument("--check", action="store_true", help="exit 1 if committed files differ from a fresh run")
    args = ap.parse_args(argv)

    cfg = yaml.safe_load(args.scenario.read_text())
    files = generate(cfg)
    stale = []
    for rel, content in files.items():
        p = args.out / rel
        if args.check:
            if not p.exists() or p.read_text() != content:
                stale.append(rel)
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    if args.check:
        if stale:
            print("Out of date (run generator/generate.py):\n  " + "\n  ".join(stale))
            return 1
        print("Generated files are up to date.")
        return 0

    users = list(csv.DictReader(io.StringIO(files[f"lab/{LAB}/files/users.csv"])))
    students = [u for u in users if u["Title"] == "Student" and "Disabled" not in u["Path"]]
    teachers = [u for u in users if "OU=Teachers" in u["Path"]]
    print(f"Wrote {len(files)} files. OUs: {len(json.loads(files[f'lab/{LAB}/files/ou_tree.json']))}, "
          f"bulk users: {len(users)} ({len(students)} students, {len(teachers)} teachers), "
          f"story accounts: {len(cfg.get('story_accounts', []))}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
