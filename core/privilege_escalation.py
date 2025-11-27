"""
privilege_escalation.py
Analyzes privilege escalation vectors:
- sudo configuration
- NOPASSWD
- Environment variable risks
- GTFOBins exploitable SUID binaries
- PATH hijacking
- Writable systemd units (fed from services module)
- Modprobe hijack possibilities
- Containerization sockets/binaries
"""

import os
import stat
from typing import Dict, Any, Callable, List

WHITELIST_CMDS = {"sudo", "which"}


GTFOBINS_SUID = {
    "bash": "Can spawn shell with elevated privileges (bash -p).",
    "find": "Execute commands via -exec.",
    "less": "Escalation via shell escapes.",
    "more": "Escalation via shell escapes.",
    "vim": "Can run :! shell unless restricted.",
    "nano": "Potential file editing on root-owned files (less severe).",
    "python": "os.setuid calls, interactive shell spawn.",
    "python3": "os.setuid calls, interactive shell spawn.",
    "perl": "Can execute system calls.",
    "awk": "Execute system commands inside script.",
    "tar": "--checkpoint/action exploit.",
    "env": "Manipulate environment to spawn shell.",
    "sh": "Direct shell access.",
    "dash": "Direct shell access."
}

CONTAINER_CMDS = ["docker", "podman", "ctr", "virsh", "kubectl"]
CONTAINER_SOCKETS = [
    "/var/run/docker.sock", "/run/podman/podman.sock", "/var/run/libvirt/libvirt-sock"
]


def safe_run(run_func: Callable, cmd: str, timeout: int = 5):
    base = cmd.split()[0]
    if base not in WHITELIST_CMDS:
        return 127, "", f"Command '{base}' not allowed"
    return run_func(cmd, timeout=timeout, shell=False)


def analyze_privilege_escalation(run_func: Callable, fs_data: Dict[str, Any], services_data: Dict[str, Any]) -> Dict[str, Any]:
    data: Dict[str, Any] = {}

    # sudo -l
    code, sudo_out, sudo_err = safe_run(run_func, "sudo -l -n", timeout=8)
    data["sudo_raw"] = sudo_out if code == 0 else f"sudo not accessible: {sudo_err}"
    data["sudo_nopasswd"] = find_nopasswd_entries(sudo_out) if code == 0 else []

    # PATH analysis
    data["path_issues"], data["path_writable"] = analyze_path()

    # Environment variables
    data["env_risky"] = analyze_environment()

    # GTFOBins exploitable SUID
    suid_bins = fs_data.get("suid_binaries", [])
    data["exploitable_suid"] = match_gtfobins(suid_bins)

    # Writable systemd units
    data["writable_units"] = services_data.get("writable_units", [])

    # Modprobe hijack
    data["modprobe_hijack"] = check_modprobe_hijack()

    # Containerization vectors
    data["containers"] = detect_containers()

    return data


def find_nopasswd_entries(text: str) -> List[str]:
    entries = []
    for line in text.splitlines():
        if "NOPASSWD" in line:
            entries.append(line.strip())
    return entries


def analyze_path():
    path = os.environ.get("PATH", "")
    parts = [p for p in path.split(":") if p]
    issues = []
    writable_dirs = []
    for idx, p in enumerate(parts):
        if p == ".":
            issues.append("PATH contains '.' element.")
        if not os.path.isdir(p):
            issues.append(f"PATH entry not a directory: {p}")
            continue
        try:
            st = os.stat(p)
            if bool(st.st_mode & stat.S_IWOTH):
                issues.append(f"World-writable PATH directory: {p} (position {idx})")
                writable_dirs.append(p)
        except Exception:
            issues.append(f"Cannot stat PATH directory: {p}")
    if "" in path.split(":"):
        issues.append("PATH contains empty element (leading/trailing ':').")
    return issues, writable_dirs


def analyze_environment():
    risky = []
    watch = ["LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PATH", "TMPDIR"]
    for k, v in os.environ.items():
        if k in watch:
            risky.append(f"{k}={v}")
    return risky


def match_gtfobins(paths: List[str]) -> List[Dict[str, str]]:
    results = []
    for p in paths:
        base = os.path.basename(p)
        if base in GTFOBINS_SUID:
            results.append({"path": p, "binary": base, "note": GTFOBINS_SUID[base]})
    return results


def check_modprobe_hijack():
    """
    Checks modprobe path existence and whether its directory or config paths are writable.
    Potential vector: altering modprobe executable or config to inject malicious modules.
    """
    findings = []
    modprobe_path = "/sbin/modprobe"
    if os.path.exists(modprobe_path):
        try:
            st = os.stat(modprobe_path)
            if bool(st.st_mode & stat.S_IWOTH):
                findings.append(f"modprobe binary is world-writable: {modprobe_path}")
        except Exception:
            pass
    cfg_dir = "/etc/modprobe.d"
    if os.path.isdir(cfg_dir):
        try:
            for f in os.listdir(cfg_dir):
                path = os.path.join(cfg_dir, f)
                try:
                    st = os.stat(path)
                    if bool(st.st_mode & stat.S_IWOTH):
                        findings.append(f"World-writable modprobe config: {path}")
                except Exception:
                    continue
        except Exception:
            pass
    if not findings:
        findings.append("No obvious modprobe hijack found.")
    return findings


def detect_containers():
    results = []
    for cmd in CONTAINER_CMDS:
        p = f"/usr/bin/{cmd}"
        if os.path.exists(p):
            results.append(cmd)
    for sock in CONTAINER_SOCKETS:
        if os.path.exists(sock):
            results.append(f"socket:{sock}")
    return results
