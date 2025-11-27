"""
filesystem.py
Scans world-writable directories/files, SUID/SGID binaries, tracks changes vs cache,
and identifies potentially dangerous permission setups.

Performance Optimizations:
- Uses find (if available) limited with -xdev
- Falls back to Python os.walk (depth-limited) if find fails
- Skips /proc, /sys, /dev, /run for expensive operations
"""

import os
import stat
from typing import Dict, Any, Callable, List, Set

WHITELIST_CMDS = {"find"}


SKIP_DIRS = {"/proc", "/sys", "/dev", "/run", "/var/lib/docker", "/var/lib/containers"}
MAX_DEPTH_FALLBACK = 6  # fallback walk depth


def safe_run(run_func: Callable, cmd: str, timeout: int = 30, shell=True):
    base = cmd.split()[0]
    if base not in WHITELIST_CMDS:
        return 127, "", f"Command '{base}' not allowed"
    return run_func(cmd, timeout=timeout, shell=shell)


def collect_filesystem(run_func: Callable, previous_cache: Dict[str, Any]) -> Dict[str, Any]:
    data: Dict[str, Any] = {}

    # World-writable directories/files using find
    ww_dirs = find_world_writable(run_func, dirs=True)
    ww_files = find_world_writable(run_func, dirs=False)

    data["world_writable_dirs"] = ww_dirs
    data["world_writable_files"] = ww_files

    # SUID SGID
    suid = find_suid_sgid(run_func, suid=True)
    sgid = find_suid_sgid(run_func, suid=False)
    data["suid_binaries"] = suid
    data["sgid_binaries"] = sgid

    prev_suid = set(previous_cache.get("suid_binaries", []))
    prev_listeners = set(previous_cache.get("listeners", []))

    new_suid = sorted(set(suid) - prev_suid)
    data["new_suid_binaries"] = new_suid

    # Critical files permission check
    critical = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/fstab", "/etc/hosts"]
    crit_perms = {}
    crit_wrong = []
    for path in critical:
        perm = get_perm_string(path)
        crit_perms[path] = perm
        if is_world_writable(path):
            crit_wrong.append(path)
    data["critical_file_permissions"] = crit_perms
    data["critical_wrong_permissions"] = crit_wrong

    return data


def find_world_writable(run_func: Callable, dirs: bool) -> List[str]:
    typ = "d" if dirs else "f"
    code, out, _ = safe_run(run_func, f"find / -xdev -type {typ} -perm -0002 2>/dev/null")
    if code == 0 and out:
        return out.splitlines()
    # Fallback
    results = []
    for root, dirnames, filenames in os.walk("/"):
        if any(root.startswith(skip) for skip in SKIP_DIRS):
            continue
        depth = root.count(os.sep)
        if depth > MAX_DEPTH_FALLBACK:
            continue
        try:
            st = os.stat(root)
        except Exception:
            continue
        if dirs:
            if bool(st.st_mode & stat.S_IWOTH):
                results.append(root)
        else:
            for fn in filenames:
                path = os.path.join(root, fn)
                try:
                    stf = os.stat(path)
                    if bool(stf.st_mode & stat.S_IWOTH):
                        results.append(path)
                except Exception:
                    continue
    return results


def find_suid_sgid(run_func: Callable, suid: bool) -> List[str]:
    perm = "-4000" if suid else "-2000"
    code, out, _ = safe_run(run_func, f"find / -xdev -perm {perm} -type f 2>/dev/null")
    if code == 0 and out:
        return out.splitlines()
    # Fallback limited walk
    results = []
    for root, _dirs, files in os.walk("/"):
        if any(root.startswith(skip) for skip in SKIP_DIRS):
            continue
        depth = root.count(os.sep)
        if depth > MAX_DEPTH_FALLBACK:
            continue
        for f in files:
            path = os.path.join(root, f)
            try:
                st = os.stat(path)
                if suid and bool(st.st_mode & stat.S_ISUID):
                    results.append(path)
                if not suid and bool(st.st_mode & stat.S_ISGID):
                    results.append(path)
            except Exception:
                continue
    return results


def get_perm_string(path: str) -> str:
    try:
        st = os.stat(path)
        return stat.filemode(st.st_mode)
    except Exception:
        return "N/A"


def is_world_writable(path: str) -> bool:
    try:
        st = os.stat(path)
        return bool(st.st_mode & stat.S_IWOTH)
    except Exception:
        return False
