"""
services.py
Enumerates systemd services (running, failed), inspects unit file permissions,
and detects writable unit files that could enable privilege escalation.

Notes:
- Requires systemd; if absent, returns graceful fallback.
- Does NOT modify any units.
"""

import os
import stat
from typing import Dict, Any, Callable, List

WHITELIST_CMDS = {"systemctl"}


def safe_run(run_func: Callable, cmd: str, timeout: int = 5):
    base = cmd.split()[0]
    if base not in WHITELIST_CMDS:
        return 127, "", f"Command '{base}' not allowed"
    return run_func(cmd, timeout=timeout, shell=False)


SYSTEMD_UNIT_DIRS = [
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system"
]


def collect_services(run_func: Callable) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    code, running, _ = safe_run(run_func, "systemctl list-units --type=service --state=running --no-pager")
    code_f, failed, _ = safe_run(run_func, "systemctl --failed --no-pager")
    data["running_services"] = running if code == 0 else "systemd not accessible"
    data["failed_services"] = failed if code_f == 0 else "systemd not accessible"
    data["writable_units"] = find_writable_units()
    return data


def find_writable_units() -> List[str]:
    writable = []
    for d in SYSTEMD_UNIT_DIRS:
        if not os.path.isdir(d):
            continue
        try:
            for entry in os.listdir(d):
                if not entry.endswith(".service"):
                    continue
                path = os.path.join(d, entry)
                try:
                    st = os.stat(path)
                    # world-writable or group-writable for non-root usage
                    if bool(st.st_mode & stat.S_IWOTH) or bool(st.st_mode & stat.S_IWGRP):
                        writable.append(path)
                except Exception:
                    continue
        except Exception:
            continue
    return writable
