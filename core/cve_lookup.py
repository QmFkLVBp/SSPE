"""
cve_lookup.py
Offline CVE matching:

Mechanism:
- Loads local JSON feeds (NVD-like) from one of:
  ./cve_data/
  /var/cache/sspe/cve/
  ~/.cache/sspe/cve/
- Expects JSON list entries of form:
  {
    "cve": "CVE-2024-XXXX",
    "product": "sudo",
    "version_pattern": "^1\\.9\\.",
    "cvss": 7.5,
    "summary": "Short description"
  }
- Matches package names & versions against regex patterns.

Falls back to a small static dictionary if no feeds available.
"""

import os
import json
import re
from typing import List, Dict


FALLBACK_CVES = [
    {
        "cve": "CVE-2021-3156",
        "product": "sudo",
        "version_pattern": ".*",
        "cvss": 7.8,
        "summary": "Baron Samedit heap overflow in sudo."
    }
]


def load_local_cve_feeds() -> List[Dict]:
    paths = [
        "./cve_data",
        "/var/cache/sspe/cve",
        os.path.expanduser("~/.cache/sspe/cve")
    ]
    entries = []
    for base in paths:
        if os.path.isdir(base):
            for f in os.listdir(base):
                if not f.endswith(".json"):
                    continue
                fp = os.path.join(base, f)
                try:
                    with open(fp, "r", encoding="utf-8") as h:
                        data = json.load(h)
                        if isinstance(data, list):
                            for item in data:
                                if _valid_cve_item(item):
                                    entries.append(item)
                except Exception:
                    continue
    if not entries:
        entries = FALLBACK_CVES
    return entries


def _valid_cve_item(item: Dict) -> bool:
    req = {"cve", "product", "version_pattern", "cvss"}
    return all(k in item for k in req)


def match_cves(packages: List[Dict[str, str]], cve_entries: List[Dict]) -> List[Dict]:
    findings = []
    for pkg in packages:
        name = pkg["name"]
        version = pkg["version"]
        for entry in cve_entries:
            if entry["product"].lower() == name.lower():
                pattern = entry["version_pattern"]
                try:
                    if re.search(pattern, version):
                        findings.append({
                            "cve": entry["cve"],
                            "product": name,
                            "version": version,
                            "cvss": entry["cvss"],
                            "summary": entry.get("summary", "")
                        })
                except re.error:
                    continue
    return findings
