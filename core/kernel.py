"""
kernel.py
Performs kernel and sysctl hardening assessment, module enumeration, dmesg anomaly scan,
and produces a heatmap dataset for PDF reporting.

Features:
- Reads kernel config from /boot/config-$(uname -r) or /proc/config.gz
- Evaluates security-relevant sysctl flags
- Collects loaded modules and flags world-writable module directories
- Extracts last dmesg lines and finds anomaly patterns
"""

import os
import re
import stat
from typing import Dict, Any, Callable, List, Tuple

WHITELIST_CMDS = {"uname", "lsmod", "dmesg", "zcat"}


def safe_run(run_func: Callable, cmd: str, timeout: int = 5, shell=False):
    base = cmd.split()[0]
    if base not in WHITELIST_CMDS:
        return 127, "", f"Command '{base}' not allowed"
    return run_func(cmd, timeout=timeout, shell=shell)


DMESG_PATTERNS = {
    "segfault": "Segfault",
    "call trace": "Call Trace",
    "oops": "Oops",
    "panic": "Panic",
    "stack protector": "Stack Protector",
    "tainted": "Tainted",
    "denied": "Denied",
    "error": "Error",
    "audit": "Audit"
}

SYSCTL_FLAGS = [
    ("kernel.kptr_restrict", 2),
    ("kernel.yama.ptrace_scope", 1),
    ("kernel.dmesg_restrict", 1),
    ("kernel.unprivileged_bpf_disabled", 1),
    ("kernel.unprivileged_userns_clone", 0),
    ("fs.protected_symlinks", 1),
    ("fs.protected_hardlinks", 1),
    ("net.ipv4.conf.all.rp_filter", 1),
    ("net.ipv4.conf.default.rp_filter", 1),
    ("net.ipv4.conf.all.accept_redirects", 0),
    ("net.ipv4.conf.all.accept_source_route", 0),
    ("net.ipv4.icmp_echo_ignore_broadcasts", 1),
]


def collect_kernel_data(run_func: Callable) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    # Kernel release
    code, rel, _ = safe_run(run_func, "uname -r")
    data["kernel_release"] = rel.strip()

    # Kernel config
    cfg = read_kernel_config(run_func, rel.strip())
    data.update(cfg)

    # Sysctl flags
    data["sysctl"] = assess_sysctl_flags()

    # Modules
    code, lsmod_out, _ = safe_run(run_func, "lsmod")
    data["modules"] = lsmod_out

    # Writable module directories
    data["writable_module_dirs"] = find_writable_module_dirs(rel.strip())

    # dmesg anomalies (last 300 lines)
    code, dmesg_out, _ = safe_run(run_func, "dmesg", timeout=10)
    last_lines = "\n".join(dmesg_out.splitlines()[-300:]) if code == 0 else ""
    data["dmesg_last"] = last_lines
    flags, counts = analyze_dmesg(last_lines)
    data["dmesg_flags"] = flags
    data["dmesg_flag_counts"] = counts

    # Heatmap dataset (binary secure/insecure mapping)
    data["heatmap"] = build_kernel_heatmap(data["sysctl"])

    return data


def read_kernel_config(run_func: Callable, release: str) -> Dict[str, Any]:
    paths = [f"/boot/config-{release}", "/proc/config.gz"]
    for p in paths:
        if os.path.exists(p):
            try:
                if p.endswith(".gz"):
                    code, out, _ = safe_run(run_func, "zcat /proc/config.gz", shell=True)
                    if code == 0:
                        return {
                            "kernel_config_path": p,
                            "kernel_config_excerpt": "\n".join(out.splitlines()[:60]),
                            "kernel_config_full": out
                        }
                else:
                    with open(p, "r", errors="ignore") as f:
                        full = f.read()
                        return {
                            "kernel_config_path": p,
                            "kernel_config_excerpt": "\n".join(full.splitlines()[:60]),
                            "kernel_config_full": full
                        }
            except Exception:
                continue
    return {
        "kernel_config_path": "not found",
        "kernel_config_excerpt": "",
        "kernel_config_full": ""
    }


def assess_sysctl_flags() -> Dict[str, Dict[str, Any]]:
    results: Dict[str, Dict[str, Any]] = {}
    for key, desired in SYSCTL_FLAGS:
        val = read_sysctl(key)
        secure = None
        try:
            secure = (int(val) == desired)
        except Exception:
            secure = False
        results[key] = {"value": val, "desired": desired, "secure": secure}
    return results


def read_sysctl(key: str) -> str:
    path = "/proc/sys/" + key.replace(".", "/")
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except Exception:
        return "unavailable"


def find_writable_module_dirs(release: str) -> List[str]:
    base = f"/lib/modules/{release}"
    writable = []
    if os.path.isdir(base):
        for root, dirs, _files in os.walk(base):
            try:
                st = os.stat(root)
                if bool(st.st_mode & stat.S_IWOTH):
                    writable.append(root)
            except Exception:
                continue
    return writable


def analyze_dmesg(text: str) -> Tuple[List[str], Dict[str, int]]:
    flags = []
    counts = {}
    lower = text.lower()
    for patt, label in DMESG_PATTERNS.items():
        c = lower.count(patt)
        if c > 0:
            flags.append(f"{label} ({c})")
            counts[label] = c
    return flags, counts


def build_kernel_heatmap(sysctl_results: Dict[str, Dict[str, Any]]) -> List[List[int]]:
    # Simple matrix: each row is [secure (1/0), current_value_as_int_or_0]
    matrix = []
    for k, meta in sysctl_results.items():
        val_raw = meta["value"]
        try:
            val_int = int(val_raw)
        except Exception:
            val_int = 0
        secure_flag = 1 if meta["secure"] else 0
        matrix.append([secure_flag, val_int])
    return matrix
