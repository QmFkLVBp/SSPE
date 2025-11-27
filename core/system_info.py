"""
system_info.py
Collects system, kernel, hardware, user/session metadata in a read-only manner.

Design Principles:
- Offline-first
- Uses only whitelisted system commands
- Falls back gracefully if a command is missing
- Avoids shell pipelines (parses in Python)
"""

import os
import re
import datetime
from typing import Dict, Any, Callable

WHITELIST_CMDS = {
    "uname", "lsblk", "lscpu", "free", "lspci", "hyprctl", "pacman"
}


def safe_run(run_func: Callable, cmd: str, timeout: int = 5):
    """Wrapper enforcing command whitelist before delegating to global safe_run."""
    base = cmd.split()[0]
    if base not in WHITELIST_CMDS:
        return 127, "", f"Command '{base}' not allowed"
    return run_func(cmd, timeout=timeout, shell=False)


def collect_system_info(run_func: Callable) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    info["timestamp"] = datetime.datetime.utcnow().isoformat() + "Z"

    # OS release
    info["os_release"] = read_file("/etc/os-release")

    # Kernel
    code, kernel_full, _ = safe_run(run_func, "uname -a")
    info["kernel_full"] = kernel_full.strip()
    code, kernel_rel, _ = safe_run(run_func, "uname -r")
    info["kernel_release"] = kernel_rel.strip()

    # Host/user
    info["hostname"] = os.uname().nodename
    info["user"] = os.environ.get("USER") or os.environ.get("LOGNAME") or "unknown"
    info["shell"] = os.environ.get("SHELL", "unknown")

    # CPU
    code, lscpu_out, _ = safe_run(run_func, "lscpu")
    info["cpu_info"] = lscpu_out

    # Memory
    code, free_out, _ = safe_run(run_func, "free -h")
    info["memory_info"] = free_out

    # GPU / Display
    code, lspci_out, _ = safe_run(run_func, "lspci")
    if code == 0:
        gpu_lines = [l for l in lspci_out.splitlines() if re.search(r"VGA|3D|Display", l, re.I)]
        info["gpu_devices"] = gpu_lines
    else:
        info["gpu_devices"] = []

    # Disk layout
    code, lsblk_out, _ = safe_run(run_func, "lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT")
    info["disk_layout"] = lsblk_out

    # Hyprland
    code, hypr_out, _ = safe_run(run_func, "hyprctl version")
    info["hyprland_version"] = hypr_out.strip() if code == 0 else "not detected"

    # Pacman packages count
    pkg_list = list_pacman_packages(run_func)
    info["package_count"] = len(pkg_list)
    info["packages_sample"] = pkg_list[:25]

    return info


def read_file(path: str) -> str:
    try:
        if os.path.exists(path):
            with open(path, "r", errors="ignore") as f:
                return f.read().strip()
    except Exception:
        pass
    return "unavailable"


def list_pacman_packages(run_func: Callable):
    pkgs = []
    # Use direct parsing: pacman -Q
    code, out, _ = safe_run(run_func, "pacman -Q")
    if code == 0:
        for line in out.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                pkgs.append({"name": parts[0], "version": parts[1]})
    return pkgs
