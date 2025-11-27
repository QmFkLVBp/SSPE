"""
network.py
Collects networking information: listening sockets, interfaces, routes,
and detects new listeners compared to previous cache.

Notes:
- Uses ss and ip (whitelisted)
- Parsing done in Python without shell pipelines
"""

import re
from typing import Dict, Any, Callable, List

WHITELIST_CMDS = {"ss", "ip"}


def safe_run(run_func: Callable, cmd: str, timeout: int = 5):
    base = cmd.split()[0]
    if base not in WHITELIST_CMDS:
        return 127, "", f"Command '{base}' not allowed"
    return run_func(cmd, timeout=timeout, shell=False)


def collect_network(run_func: Callable, previous_cache: Dict[str, Any]) -> Dict[str, Any]:
    data: Dict[str, Any] = {}

    code, ss_out, _ = safe_run(run_func, "ss -tulnp")
    data["listeners_raw"] = ss_out if code == 0 else ""
    listeners = parse_listeners(ss_out) if code == 0 else []
    data["listeners"] = listeners

    prev_listeners = set(previous_cache.get("listeners", []))
    new_list = sorted(set(listeners) - prev_listeners)
    data["new_listeners"] = new_list

    code, route_out, _ = safe_run(run_func, "ip route")
    data["routes"] = route_out if code == 0 else ""

    code, iface_out, _ = safe_run(run_func, "ip -br addr")
    data["interfaces"] = iface_out if code == 0 else ""

    return data


def parse_listeners(ss_text: str) -> List[str]:
    results = []
    for line in ss_text.splitlines():
        if re.search(r"LISTEN|UNCONN", line):
            results.append(line.strip())
    return results
