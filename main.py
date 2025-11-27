"""
main.py
Entry point for SSPE-Analyzer.

Workflow:
1. Initialize terminal UI (Rich if available).
2. Load previous cache (if any) for delta detection (SUID, listeners).
3. Run scanning modules in parallel ThreadPoolExecutor.
4. Perform CVE lookup (after packages).
5. Compute findings, severity classification, and score.
6. Generate TXT, JSON, PDF reports.
7. Persist new cache for next run.

Caching:
- Primary path: /var/cache/sspe/cache.json (may require elevated perms)
- Fallback: ~/.cache/sspe/cache.json

All operations are read-only except writing reports & cache.

Safety:
- safe_run restricts allowed commands (whitelist)
- No execution of unknown binaries
- No network connections
"""

import os
import json
import stat
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, Tuple, List

# Import modules
from core.system_info import collect_system_info
from core.services import collect_services
from core.processes import collect_processes
from core.packages import collect_packages, get_package_versions
from core.kernel import collect_kernel_data
from core.filesystem import collect_filesystem
from core.network import collect_network
from core.privilege_escalation import analyze_privilege_escalation
from core.cve_lookup import load_local_cve_feeds, match_cves
from report.txt_report import generate_txt_report
from report.json_report import generate_json_report
from report.pdf_report import generate_pdf
from report.charts import severity_bar, category_pie, kernel_heatmap, suid_distribution
from ui.terminal_ui import TerminalUI

import subprocess
import shlex

CACHE_PRIMARY = "/var/cache/sspe/cache.json"
CACHE_FALLBACK = os.path.expanduser("~/.cache/sspe/cache.json")

REPORT_DIR = os.path.expanduser("~/SSPE-Analyzer/reports")
os.makedirs(REPORT_DIR, exist_ok=True)

TIMESTAMP = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
TXT_PATH = os.path.join(REPORT_DIR, f"{TIMESTAMP}.txt")
JSON_PATH = os.path.join(REPORT_DIR, f"{TIMESTAMP}.json")
PDF_PATH = os.path.join(REPORT_DIR, f"{TIMESTAMP}.pdf")

WHITELIST_COMMANDS = {
    "uname", "lsblk", "lscpu", "free", "lspci", "hyprctl", "pacman", "systemctl",
    "ps", "ss", "ip", "sudo", "find", "lsmod", "dmesg", "zcat", "which"
}


def safe_run(cmd: str, timeout: int = 5, shell: bool = False) -> Tuple[int, str, str]:
    """
    Safely execute whitelisted commands only.
    Returns (code, stdout, stderr). Truncates large output.
    """
    base = cmd.split()[0]
    if base not in WHITELIST_COMMANDS:
        return 127, "", f"Command '{base}' blocked"
    try:
        args = cmd if shell else shlex.split(cmd)
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=shell)
        stdout, stderr = proc.communicate(timeout=timeout)
        stdout = sanitize(stdout)
        stderr = sanitize(stderr)
        return proc.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        return 124, "", "Timeout"
    except FileNotFoundError:
        return 127, "", "Not found"
    except Exception as e:
        return 1, "", f"Error: {e}"


def sanitize(text: str) -> str:
    if text is None:
        return ""
    clean = "".join(ch if ch.isprintable() or ch in "\n\r\t" else "?" for ch in text)
    if len(clean) > 150000:
        clean = clean[:150000] + "\n...[TRUNCATED]"
    return clean.strip()


def load_previous_cache() -> Dict[str, Any]:
    path = CACHE_PRIMARY
    if not os.path.exists(path):
        path = CACHE_FALLBACK
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_cache(data: Dict[str, Any]):
    path = CACHE_PRIMARY
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return
    except Exception:
        # fallback
        path = CACHE_FALLBACK
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass


def compute_findings(analysis: Dict[str, Any]) -> Tuple[List[Dict[str, str]], Dict[str, int], Dict[str, int]]:
    findings = []
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    category_counts = {}

    def add(title: str, severity: str, category: str):
        findings.append({"title": title, "severity": severity, "category": category})
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        category_counts[category] = category_counts.get(category, 0) + 1

    fs = analysis["filesystem"]
    pe = analysis["privilege_escalation"]
    krn = analysis["kernel"]
    net = analysis["network"]
    services = analysis["services"]

    # Filesystem
    total_ww = len(fs["world_writable_dirs"]) + len(fs["world_writable_files"])
    if total_ww:
        sev = "Low" if total_ww <= 10 else ("Medium" if total_ww <= 50 else "High")
        add(f"World-writable paths: {total_ww}", sev, "Filesystem")
    if fs["critical_wrong_permissions"]:
        add(f"Critical files world-writable: {len(fs['critical_wrong_permissions'])}", "Critical", "Filesystem")
    if fs["new_suid_binaries"]:
        add(f"New SUID binaries since last run: {len(fs['new_suid_binaries'])}", "High", "Privilege Escalation")
    suid_count = len(fs["suid_binaries"])
    if suid_count:
        sev = "Medium" if suid_count <= 20 else ("High" if suid_count <= 50 else "Critical")
        add(f"SUID binaries present: {suid_count}", sev, "Privilege Escalation")

    # Priv Esc
    if pe["sudo_nopasswd"]:
        add("NOPASSWD sudo entries present", "High", "Privilege Escalation")
    if pe["exploitable_suid"]:
        add(f"Exploitable SUID binaries: {len(pe['exploitable_suid'])}", "High", "Privilege Escalation")
    if pe["path_writable"]:
        add(f"Writable PATH directories: {len(pe['path_writable'])}", "Medium", "Privilege Escalation")
    if pe["modprobe_hijack"] and any("world-writable" in m for m in pe["modprobe_hijack"]):
        add("Potential modprobe hijack writable paths", "Medium", "Privilege Escalation")

    # Kernel
    weak_sysctl = sum(1 for v in krn["sysctl"].values() if not v["secure"])
    if weak_sysctl:
        sev = "Medium" if weak_sysctl <= 5 else "High"
        add(f"Weak sysctl hardening flags: {weak_sysctl}", sev, "Kernel")
    if krn["writable_module_dirs"]:
        add(f"Writable kernel module directories: {len(krn['writable_module_dirs'])}", "High", "Kernel")
    if krn["dmesg_flags"]:
        sev = "Low" if len(krn["dmesg_flags"]) <= 2 else ("Medium" if len(krn["dmesg_flags"]) <= 5 else "High")
        add(f"dmesg anomaly patterns: {len(krn['dmesg_flags'])}", sev, "Kernel")

    # Network
    listeners = len(net["listeners"])
    if listeners:
        sev = "Low" if listeners <= 3 else ("Medium" if listeners <= 10 else "High")
        add(f"Listening services: {listeners}", sev, "Network")
    if net["new_listeners"]:
        add(f"New listeners since last run: {len(net['new_listeners'])}", "Medium", "Network")

    # Services
    if services.get("writable_units"):
        add(f"Writable systemd units: {len(services['writable_units'])}", "High", "Services")

    return findings, severity_counts, category_counts


def compute_score(findings: List[Dict[str, str]], analysis: Dict[str, Any], severity_counts: Dict[str, int]) -> Dict[str, Any]:
    score = 100
    deductions = []

    fs = analysis["filesystem"]
    pe = analysis["privilege_escalation"]
    krn = analysis["kernel"]
    net = analysis["network"]

    suid_count = len(fs["suid_binaries"])
    if suid_count > 50:
        score -= 20
        deductions.append(f"High SUID count ({suid_count}) -20")
    elif suid_count > 20:
        score -= 10
        deductions.append(f"Moderate SUID count ({suid_count}) -10")
    elif suid_count > 10:
        score -= 5
        deductions.append(f"Elevated SUID count ({suid_count}) -5")

    ww_total = len(fs["world_writable_dirs"]) + len(fs["world_writable_files"])
    if ww_total > 200:
        score -= 25
        deductions.append(f"Excessive world-writable paths ({ww_total}) -25")
    elif ww_total > 50:
        score -= 15
        deductions.append(f"Large number of world-writable paths ({ww_total}) -15")
    elif ww_total > 10:
        score -= 5
        deductions.append(f"Some world-writable paths ({ww_total}) -5")

    if pe["sudo_nopasswd"]:
        score -= 15
        deductions.append("NOPASSWD sudo entries -15")

    if pe["exploitable_suid"]:
        score -= 10
        deductions.append("Exploitable SUID binaries -10")

    weak_sysctl = sum(1 for v in krn["sysctl"].values() if not v["secure"])
    if weak_sysctl > 10:
        score -= 20
        deductions.append(f"Many weak sysctl flags ({weak_sysctl}) -20")
    elif weak_sysctl > 5:
        score -= 10
        deductions.append(f"Several weak sysctl flags ({weak_sysctl}) -10")
    elif weak_sysctl > 0:
        score -= 5
        deductions.append(f"Some weak sysctl flags ({weak_sysctl}) -5")

    listeners = len(net["listeners"])
    if listeners > 30:
        score -= 20
        deductions.append(f"Many open listeners ({listeners}) -20")
    elif listeners > 10:
        score -= 10
        deductions.append(f"Elevated open listeners ({listeners}) -10")
    elif listeners > 3:
        score -= 5
        deductions.append(f"Some open listeners ({listeners}) -5")

    writable_units = len(analysis["services"].get("writable_units", []))
    if writable_units:
        score -= 10
        deductions.append(f"Writable systemd units ({writable_units}) -10")

    if krn["writable_module_dirs"]:
        score -= 10
        deductions.append("Writable kernel module directories -10")

    if fs["critical_wrong_permissions"]:
        score -= 15
        deductions.append("Critical files world-writable -15")

    if score < 0:
        score = 0

    if score >= 80:
        assessment = "Secure / Hardened (minor improvements possible)."
    elif score >= 60:
        assessment = "Moderate – improvements recommended."
    elif score >= 40:
        assessment = "At Risk – multiple issues present."
    else:
        assessment = "Critical – immediate remediation required."

    return {
        "value": score,
        "deductions": deductions,
        "severity_counts": severity_counts,
        "assessment": assessment
    }


def generate_charts(analysis: Dict[str, Any], severity_counts: Dict[str, int], category_counts: Dict[str, int]) -> Dict[str, Any]:
    charts = {}
    charts["Severity Distribution"] = severity_bar(severity_counts)
    charts["Category Breakdown"] = category_pie(category_counts)
    charts["Kernel Heatmap"] = kernel_heatmap(analysis["kernel"]["heatmap"])
    charts["SUID/SGID Distribution"] = suid_distribution(analysis["filesystem"]["suid_binaries"],
                                                         analysis["filesystem"]["sgid_binaries"])
    return charts


def main():
    ui = TerminalUI()
    tasks_order = [
        "system_info", "services", "processes", "packages",
        "kernel", "filesystem", "network"
    ]
    ui.start(total_tasks=len(tasks_order) + 4)  # + PE, CVE, scoring, reporting

    previous_cache = load_previous_cache()

    results: Dict[str, Any] = {}

    with ThreadPoolExecutor(max_workers=6) as executor:
        future_map = {}
        for name in tasks_order:
            if name == "system_info":
                future_map[executor.submit(collect_system_info, safe_run)] = name
            elif name == "services":
                future_map[executor.submit(collect_services, safe_run)] = name
            elif name == "processes":
                future_map[executor.submit(collect_processes, safe_run)] = name
            elif name == "packages":
                future_map[executor.submit(collect_packages, safe_run)] = name
            elif name == "kernel":
                future_map[executor.submit(collect_kernel_data, safe_run)] = name
            elif name == "filesystem":
                future_map[executor.submit(collect_filesystem, safe_run, previous_cache)] = name
            elif name == "network":
                future_map[executor.submit(collect_network, safe_run, previous_cache)] = name

        for fut in as_completed(future_map):
            name = future_map[fut]
            try:
                results[name] = fut.result()
            except Exception as e:
                results[name] = {"error": str(e)}
            ui.update(f"Completed: {name}")

    # Privilege escalation (depends on filesystem + services)
    pe_data = analyze_privilege_escalation(safe_run, results["filesystem"], results["services"])
    results["privilege_escalation"] = pe_data
    ui.update("Completed: privilege escalation")

    # CVE lookup (depends on packages)
    cve_entries = load_local_cve_feeds()
    pkg_versions = get_package_versions(safe_run)
    cve_matches = match_cves(pkg_versions, cve_entries)
    results["cve"] = {"matches": cve_matches, "count": len(cve_matches)}
    ui.update("Completed: CVE lookup")

    # Findings & Score
    findings, sev_counts, cat_counts = compute_findings(results)
    score_data = compute_score(findings, results, sev_counts)
    results["score"] = score_data
    results["findings"] = findings
    results["severity_counts"] = sev_counts
    results["category_counts"] = cat_counts
    ui.update("Completed: scoring")

    # Compose unified analysis dict for report modules
    analysis = {
        **results
    }

    # TXT report
    txt_report = generate_txt_report(analysis)
    try:
        with open(TXT_PATH, "w", encoding="utf-8") as f:
            f.write(txt_report)
    except Exception:
        pass

    # JSON report
    json_report = generate_json_report(analysis)
    try:
        with open(JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(json_report, f, indent=2)
    except Exception:
        pass

    # PDF report with charts
    charts = generate_charts(analysis, sev_counts, cat_counts)
    pdf_ok, pdf_msg = generate_pdf(analysis, charts, PDF_PATH)
    ui.update(f"Completed: PDF ({'ok' if pdf_ok else pdf_msg})")

    # Save cache for next run (subset)
    cache_subset = {
        "suid_binaries": results["filesystem"].get("suid_binaries", []),
        "listeners": results["network"].get("listeners", [])
    }
    save_cache(cache_subset)

    ui.stop()

    print(f"TXT report: {TXT_PATH}")
    print(f"JSON report: {JSON_PATH}")
    if pdf_ok:
        print(f"PDF report: {PDF_PATH}")
    else:
        print(f"PDF generation failed: {pdf_msg}")
    print(f"Security Score: {score_data['value']}/100 ({score_data['assessment']})")


if __name__ == "__main__":
    main()
