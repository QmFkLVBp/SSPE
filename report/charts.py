"""
charts.py
Generates matplotlib charts (grayscale) and returns them as BytesIO objects.

Charts:
- Severity distribution (bar)
- Category distribution (pie)
- Kernel heatmap
- SUID/SGID top-level directory distribution
"""

from io import BytesIO
from typing import Dict, Any, List
import os

# Use non-interactive backend
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
plt.style.use("grayscale")


def severity_bar(severity_counts: Dict[str, int]) -> BytesIO:
    labels = ["Critical", "High", "Medium", "Low", "Info"]
    values = [severity_counts.get(l, 0) for l in labels]
    fig, ax = plt.subplots(figsize=(6, 3))
    ax.bar(labels, values)
    ax.set_title("Findings by Severity")
    ax.set_ylabel("Count")
    ax.grid(axis='y', linestyle='--', linewidth=0.5)
    bio = BytesIO()
    fig.tight_layout()
    fig.savefig(bio, format="png", bbox_inches="tight")
    plt.close(fig)
    bio.seek(0)
    return bio


def category_pie(category_counts: Dict[str, int]) -> BytesIO:
    if not category_counts:
        category_counts = {"none": 1}
    labels = list(category_counts.keys())
    sizes = [category_counts[l] for l in labels]
    fig, ax = plt.subplots(figsize=(5, 3))
    ax.pie(sizes, labels=labels, autopct="%1.0f%%", startangle=90)
    ax.set_title("Findings by Category")
    ax.axis("equal")
    bio = BytesIO()
    fig.tight_layout()
    fig.savefig(bio, format="png", bbox_inches="tight")
    plt.close(fig)
    bio.seek(0)
    return bio


def kernel_heatmap(matrix: List[List[int]]) -> BytesIO:
    if not matrix:
        matrix = [[0, 0]]
    import numpy as np
    arr = np.array(matrix)
    fig, ax = plt.subplots(figsize=(4, 4))
    im = ax.imshow(arr, cmap="Greys", aspect="auto")
    ax.set_title("Kernel Hardening Heatmap")
    ax.set_xlabel("Columns: secure_flag, current_value")
    ax.set_yticks([])
    fig.colorbar(im, ax=ax, shrink=0.7)
    bio = BytesIO()
    fig.tight_layout()
    fig.savefig(bio, format="png", bbox_inches="tight")
    plt.close(fig)
    bio.seek(0)
    return bio


def suid_distribution(suid_list: List[str], sgid_list: List[str]) -> BytesIO:
    # Categorize by top-level directory
    def top(path: str):
        parts = path.strip("/").split("/")
        return "/" + (parts[0] if parts and parts[0] else "")
    import collections
    suid_counts = collections.Counter(top(p) for p in suid_list)
    sgid_counts = collections.Counter(top(p) for p in sgid_list)
    labels = sorted(set(list(suid_counts.keys()) + list(sgid_counts.keys())))
    suid_values = [suid_counts.get(l, 0) for l in labels]
    sgid_values = [sgid_counts.get(l, 0) for l in labels]

    fig, ax = plt.subplots(figsize=(6, 3))
    width = 0.4
    x = range(len(labels))
    ax.bar([i - width / 2 for i in x], suid_values, width=width, label="SUID", hatch="//")
    ax.bar([i + width / 2 for i in x], sgid_values, width=width, label="SGID", hatch="\\\\")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.set_ylabel("Count")
    ax.set_title("SUID / SGID Distribution (Top-Level)")
    ax.grid(axis='y', linestyle='--', linewidth=0.5)
    ax.legend()
    bio = BytesIO()
    fig.tight_layout()
    fig.savefig(bio, format="png", bbox_inches="tight")
    plt.close(fig)
    bio.seek(0)
    return bio
