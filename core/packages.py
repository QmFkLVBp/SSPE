"""
packages.py
Handles package inventory and version extraction for CVE correlation.
Currently supports pacman (Arch Linux).

Offline CVE correlation handled by cve_lookup module.
"""

from typing import Dict, Any, Callable, List
from .system_info import list_pacman_packages, safe_run as sysinfo_safe_run

WHITELIST_CMDS = {"pacman"}


def collect_packages(run_func: Callable) -> Dict[str, Any]:
    pkgs = list_pacman_packages(run_func)
    return {
        "package_count": len(pkgs),
        "packages": pkgs
    }


def get_package_versions(run_func: Callable) -> List[Dict[str, str]]:
    return list_pacman_packages(run_func)
