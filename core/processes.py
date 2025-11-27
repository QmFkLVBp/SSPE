"""
processes.py
Enumerates running processes, flags suspicious patterns and potential PE indicators in command lines.

Approach:
- Uses ps output
- Heuristics only (non-invasive)
- Avoids elevated operations
"""

from typing import Dict, Any, Callable, List

WHITELIST_CMDS = {"ps"}


def safe_run(run_func: Callable, cmd: str, timeout: int = 5):
    base = cmd.split()[0]
    if base not in WHITELIST_CMDS:
        return 127, "", f"Command '{base}' not allowed"
    return run_func(cmd, timeout=timeout, shell=False)


SUSPICIOUS_PATTERNS = [
    "nc ", "ncat", "netcat", "perl ", "python -c", "bash -i", "sh -i",
    "wget ", "curl ", "telnet ", "php -r", "ruby ", "nmap ", "socat ",
    "ssh -D", "dropbear", "hydra ", "aircrack", "tcpdump", "rev ", "bash -p"
]


def collect_processes(run_func: Callable) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    code, ps_out, _ = safe_run(run_func, "ps aux")
    data["raw"] = ps_out
    data["suspicious"] = detect_suspicious(ps_out) if code == 0 else []
    return data


def detect_suspicious(ps_text: str) -> List[str]:
    flagged = []
    lower_lines = [l.lower() for l in ps_text.splitlines()]
    for line in lower_lines:
        for patt in SUSPICIOUS_PATTERNS:
            if patt in line:
                flagged.append(line)
                break
    return flagged
