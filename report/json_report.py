"""
json_report.py
Produces machine-parseable JSON structure for SIEM/API ingestion.

Schema summary (top-level keys):
- meta
- system
- services
- processes
- filesystem
- kernel
- network
- privilege_escalation
- cve
- score
"""

from typing import Dict, Any


def generate_json_report(analysis: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "meta": {
            "tool": "SSPE-Analyzer",
            "version": "2.0",
            "timestamp": analysis["system_info"]["timestamp"]
        },
        "system": analysis["system_info"],
        "services": analysis["services"],
        "processes": {
            "suspicious": analysis["processes"]["suspicious"],
            "count": len(analysis["processes"]["raw"].splitlines())
        },
        "filesystem": {
            "world_writable_dirs_count": len(analysis["filesystem"]["world_writable_dirs"]),
            "world_writable_files_count": len(analysis["filesystem"]["world_writable_files"]),
            "suid_count": len(analysis["filesystem"]["suid_binaries"]),
            "sgid_count": len(analysis["filesystem"]["sgid_binaries"]),
            "new_suid": analysis["filesystem"]["new_suid_binaries"],
            "critical_file_permissions": analysis["filesystem"]["critical_file_permissions"],
            "critical_wrong_permissions": analysis["filesystem"]["critical_wrong_permissions"],
        },
        "kernel": {
            "release": analysis["kernel"]["kernel_release"],
            "config_path": analysis["kernel"]["kernel_config_path"],
            "sysctl": analysis["kernel"]["sysctl"],
            "writable_module_dirs": analysis["kernel"]["writable_module_dirs"],
            "dmesg_flags": analysis["kernel"]["dmesg_flags"],
            "dmesg_flag_counts": analysis["kernel"]["dmesg_flag_counts"],
            "heatmap": analysis["kernel"]["heatmap"]
        },
        "network": {
            "listeners_count": len(analysis["network"]["listeners"]),
            "new_listeners": analysis["network"]["new_listeners"],
            "routes": analysis["network"]["routes"],
            "interfaces": analysis["network"]["interfaces"]
        },
        "privilege_escalation": analysis["privilege_escalation"],
        "cve": analysis["cve"],
        "score": analysis["score"]
    }
