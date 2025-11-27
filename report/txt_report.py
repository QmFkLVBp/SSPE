"""
txt_report.py
Generates clean, structured ASCII report without ANSI color,
including clear section separators and summary block.

Input: aggregated analysis dictionary
Output: multiline string
"""

import datetime
from typing import Dict, Any, List


SEP = "=" * 78
SUB_SEP = "-" * 78


def generate_txt_report(analysis: Dict[str, Any]) -> str:
    lines: List[str] = []
    now = datetime.datetime.utcnow().isoformat() + "Z"
    lines.append(SEP)
    lines.append("SSPE-Analyzer — System Security & Privilege Escalation Audit")
    lines.append(f"Generated: {now}")
    lines.append(SEP)
    lines.append("")

    # System Information
    sys_info = analysis["system_info"]
    lines.append(SEP)
    lines.append("SYSTEM INFORMATION")
    lines.append(SEP)
    for k in ["hostname", "user", "kernel_release", "hyprland_version", "package_count", "timestamp"]:
        lines.append(f"{k}: {sys_info.get(k, '')}")
    lines.append("")
    lines.append("CPU:")
    lines.append(sys_info.get("cpu_info", ""))
    lines.append("")
    lines.append("Memory:")
    lines.append(sys_info.get("memory_info", ""))
    lines.append("")
    lines.append("Disk Layout:")
    lines.append(sys_info.get("disk_layout", ""))
    lines.append("")
    lines.append("GPU Devices:")
    for g in sys_info.get("gpu_devices", []):
        lines.append(f"  {g}")
    lines.append("")

    # Services
    services = analysis["services"]
    lines.append(SEP)
    lines.append("SERVICES")
    lines.append(SEP)
    lines.append("Running Services:")
    lines.append(services.get("running_services", ""))
    lines.append("")
    lines.append("Failed Services:")
    lines.append(services.get("failed_services", ""))
    lines.append("")
    lines.append("Writable Unit Files:")
    for w in services.get("writable_units", []):
        lines.append(f"  {w}")
    lines.append("")

    # Processes
    proc = analysis["processes"]
    lines.append(SEP)
    lines.append("PROCESSES")
    lines.append(SEP)
    lines.append("Suspicious Processes:")
    for s in proc.get("suspicious", []):
        lines.append(f"  {s}")
    lines.append("")

    # Filesystem
    fs = analysis["filesystem"]
    lines.append(SEP)
    lines.append("FILESYSTEM")
    lines.append(SEP)
    lines.append(f"World-writable directories: {len(fs.get('world_writable_dirs', []))}")
    lines.append(f"World-writable files: {len(fs.get('world_writable_files', []))}")
    lines.append(f"SUID binaries: {len(fs.get('suid_binaries', []))}")
    lines.append(f"New SUID binaries (since last scan): {len(fs.get('new_suid_binaries', []))}")
    lines.append(f"SGID binaries: {len(fs.get('sgid_binaries', []))}")
    lines.append("")
    lines.append("Critical Permissions:")
    for path, perm in fs.get("critical_file_permissions", {}).items():
        lines.append(f"  {path}: {perm}")
    if fs.get("critical_wrong_permissions"):
        lines.append("Critical wrong permissions:")
        for w in fs["critical_wrong_permissions"]:
            lines.append(f"  {w}")
    lines.append("")

    # Kernel
    krn = analysis["kernel"]
    lines.append(SEP)
    lines.append("KERNEL SECURITY")
    lines.append(SEP)
    lines.append(f"Kernel Release: {krn.get('kernel_release', '')}")
    lines.append(f"Kernel Config Path: {krn.get('kernel_config_path', '')}")
    lines.append("Kernel Config Excerpt:")
    lines.append(krn.get("kernel_config_excerpt", ""))
    lines.append("")
    lines.append("Sysctl Security Flags:")
    for k, meta in krn.get("sysctl", {}).items():
        lines.append(f"  {k}: value={meta['value']} desired={meta['desired']} secure={meta['secure']}")
    lines.append("")
    lines.append("Writable Kernel Module Directories:")
    for w in krn.get("writable_module_dirs", []):
        lines.append(f"  {w}")
    lines.append("")
    lines.append("dmesg Anomalies:")
    for f in krn.get("dmesg_flags", []):
        lines.append(f"  {f}")
    lines.append("")

    # Network
    net = analysis["network"]
    lines.append(SEP)
    lines.append("NETWORK")
    lines.append(SEP)
    lines.append(f"Listeners: {len(net.get('listeners', []))}")
    lines.append(f"New listeners (since last scan): {len(net.get('new_listeners', []))}")
    lines.append("")
    lines.append("Routes:")
    lines.append(net.get("routes", ""))
    lines.append("")
    lines.append("Interfaces:")
    lines.append(net.get("interfaces", ""))
    lines.append("")

    # Privilege Escalation
    pe = analysis["privilege_escalation"]
    lines.append(SEP)
    lines.append("PRIVILEGE ESCALATION")
    lines.append(SEP)
    lines.append("sudo -l output:")
    lines.append(pe.get("sudo_raw", ""))
    lines.append("")
    lines.append("NOPASSWD entries:")
    for n in pe.get("sudo_nopasswd", []):
        lines.append(f"  {n}")
    lines.append("")
    lines.append("PATH issues:")
    for p in pe.get("path_issues", []):
        lines.append(f"  {p}")
    lines.append("")
    lines.append("Writable PATH directories:")
    for w in pe.get("path_writable", []):
        lines.append(f"  {w}")
    lines.append("")
    lines.append("Risky environment variables:")
    for e in pe.get("env_risky", []):
        lines.append(f"  {e}")
    lines.append("")
    lines.append("Exploitable SUID binaries (GTFOBins):")
    for ex in pe.get("exploitable_suid", []):
        lines.append(f"  {ex['path']} -> {ex['note']}")
    lines.append("")
    lines.append("Modprobe Hijack Findings:")
    for m in pe.get("modprobe_hijack", []):
        lines.append(f"  {m}")
    lines.append("")
    lines.append("Containerization vectors:")
    for c in pe.get("containers", []):
        lines.append(f"  {c}")
    lines.append("")

    # CVE
    cve = analysis["cve"]
    lines.append(SEP)
    lines.append("CVE MATCHES")
    lines.append(SEP)
    if cve.get("matches"):
        for m in cve["matches"]:
            lines.append(f"  {m['product']} {m['version']} -> {m['cve']} (CVSS {m['cvss']}) {m['summary']}")
    else:
        lines.append("  No local CVE matches found.")
    lines.append("")

    # Score + Findings
    score = analysis["score"]
    lines.append(SEP)
    lines.append("SECURITY SCORE")
    lines.append(SEP)
    lines.append(f"Score: {score['value']}/100")
    lines.append("Deductions:")
    for d in score.get("deductions", []):
        lines.append(f"  - {d}")
    lines.append("")
    lines.append("Severity Counts:")
    for sev, cnt in score.get("severity_counts", {}).items():
        lines.append(f"  {sev}: {cnt}")
    lines.append("")
    lines.append("Assessment: " + score.get("assessment", ""))
    lines.append("")
    lines.append(SEP)
    lines.append("END OF REPORT")
    lines.append(SEP)

    return "\n".join(lines)
