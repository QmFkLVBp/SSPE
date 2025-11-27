"""
pdf_report.py
Builds a formatted PDF report using ReportLab and embeds charts.

Sections:
- Cover page
- Table of Contents
- System, Services, Processes, Filesystem, Kernel, Network, PE, CVE, Score
- Charts page

All content is grayscale-friendly.

If ReportLab or matplotlib import fails, returns graceful failure.
"""

from typing import Dict, Any, List, Tuple

def generate_pdf(analysis: Dict[str, Any], charts: Dict[str, Any], pdf_path: str) -> Tuple[bool, str]:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Preformatted, Table, TableStyle, Image
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus.tableofcontents import TableOfContents
        from reportlab.lib.colors import black
        from reportlab.lib import enums
    except Exception as e:
        return False, f"PDF libraries unavailable: {e}"

    doc = SimpleDocTemplate(pdf_path, pagesize=A4,
                            rightMargin=42, leftMargin=42, topMargin=54, bottomMargin=54)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Mono", fontName="Courier", fontSize=8, leading=10))
    styles.add(ParagraphStyle(name="Heading1Center", parent=styles["Heading1"], alignment=enums.TA_CENTER))
    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle(fontSize=14, name='TOCHeading1', leftIndent=20, firstLineIndent=-10),
        ParagraphStyle(fontSize=12, name='TOCHeading2', leftIndent=40, firstLineIndent=-10),
    ]

    story: List[Any] = []

    def add_heading(text, level=1):
        style = styles["Heading1"] if level == 1 else styles["Heading2"]
        para = Paragraph(text, style)
        story.append(para)
        story.append(Spacer(1, 8))
        para._bookmarkName = text
        return para

    # Cover Page
    story.append(Spacer(1, 120))
    story.append(Paragraph("SSPE-Analyzer", styles["Heading1Center"]))
    story.append(Spacer(1, 24))
    story.append(Paragraph("System Security & Privilege Escalation Audit", styles["Heading2"]))
    story.append(Spacer(1, 36))
    sys_info = analysis["system_info"]
    meta_table_data = [
        ["Hostname", sys_info.get("hostname", "")],
        ["User", sys_info.get("user", "")],
        ["Kernel", sys_info.get("kernel_release", "")],
        ["Packages", str(sys_info.get("package_count", 0))],
        ["Timestamp", sys_info.get("timestamp", "")]
    ]
    from reportlab.platypus import Table
    meta_tbl = Table(meta_table_data, hAlign='LEFT', colWidths=[100, 350])
    meta_tbl.setStyle(TableStyle([
        ('LINEBELOW', (0, 0), (-1, -1), 0.25, black),
        ('FONT', (0, 0), (-1, -1), 'Helvetica', 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 12))
    story.append(Paragraph("This report is generated offline. No system modifications were performed.", styles["BodyText"]))
    story.append(PageBreak())

    # TOC
    story.append(Paragraph("Table of Contents", styles["Heading1"]))
    story.append(toc)
    story.append(PageBreak())

    # System Section
    add_heading("System Information", 1)
    story.append(Paragraph(f"Hyprland Version: {sys_info.get('hyprland_version','')}", styles["BodyText"]))
    story.append(Paragraph("CPU Information:", styles["Heading2"]))
    story.append(Preformatted(sys_info.get("cpu_info", ""), styles["Mono"]))
    story.append(Paragraph("Memory Information:", styles["Heading2"]))
    story.append(Preformatted(sys_info.get("memory_info", ""), styles["Mono"]))
    story.append(Paragraph("Disk Layout:", styles["Heading2"]))
    story.append(Preformatted(sys_info.get("disk_layout", ""), styles["Mono"]))
    story.append(Paragraph("GPU Devices:", styles["Heading2"]))
    story.append(Preformatted("\n".join(sys_info.get("gpu_devices", [])), styles["Mono"]))
    story.append(PageBreak())

    # Services
    services = analysis["services"]
    add_heading("Services", 1)
    story.append(Paragraph("Running Services:", styles["Heading2"]))
    story.append(Preformatted(services.get("running_services", ""), styles["Mono"]))
    story.append(Paragraph("Failed Services:", styles["Heading2"]))
    story.append(Preformatted(services.get("failed_services", ""), styles["Mono"]))
    story.append(Paragraph("Writable Units:", styles["Heading2"]))
    story.append(Preformatted("\n".join(services.get("writable_units", [])), styles["Mono"]))
    story.append(PageBreak())

    # Processes
    proc = analysis["processes"]
    add_heading("Processes", 1)
    story.append(Paragraph("Suspicious Processes:", styles["Heading2"]))
    story.append(Preformatted("\n".join(proc.get("suspicious", [])), styles["Mono"]))
    story.append(PageBreak())

    # Filesystem
    fs = analysis["filesystem"]
    add_heading("Filesystem", 1)
    story.append(Paragraph(f"WW Dirs: {len(fs['world_writable_dirs'])} | WW Files: {len(fs['world_writable_files'])}", styles["BodyText"]))
    story.append(Paragraph(f"SUID: {len(fs['suid_binaries'])} | SGID: {len(fs['sgid_binaries'])}", styles["BodyText"]))
    story.append(Paragraph(f"New SUID (since last): {len(fs['new_suid_binaries'])}", styles["BodyText"]))
    story.append(Paragraph("Critical File Permissions:", styles["Heading2"]))
    crit_table = Table([[p, perm] for p, perm in fs["critical_file_permissions"].items()], hAlign='LEFT', colWidths=[250, 150])
    crit_table.setStyle(TableStyle([
        ('LINEBELOW', (0, 0), (-1, -1), 0.25, black),
        ('FONT', (0, 0), (-1, -1), 'Helvetica', 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(crit_table)
    story.append(Spacer(1, 12))
    story.append(Paragraph("Critical Wrong Permissions:", styles["Heading2"]))
    story.append(Preformatted("\n".join(fs.get("critical_wrong_permissions", [])), styles["Mono"]))
    story.append(PageBreak())

    # Kernel
    krn = analysis["kernel"]
    add_heading("Kernel", 1)
    story.append(Paragraph(f"Kernel Release: {krn.get('kernel_release','')}", styles["BodyText"]))
    story.append(Paragraph(f"Config Path: {krn.get('kernel_config_path','')}", styles["BodyText"]))
    story.append(Paragraph("Config Excerpt:", styles["Heading2"]))
    story.append(Preformatted(krn.get("kernel_config_excerpt", ""), styles["Mono"]))
    story.append(Paragraph("Sysctl Flags:", styles["Heading2"]))
    sysctl_lines = []
    for k, meta in krn.get("sysctl", {}).items():
        sysctl_lines.append(f"{k} value={meta['value']} desired={meta['desired']} secure={meta['secure']}")
    story.append(Preformatted("\n".join(sysctl_lines), styles["Mono"]))
    story.append(Paragraph("Writable Module Dirs:", styles["Heading2"]))
    story.append(Preformatted("\n".join(krn.get("writable_module_dirs", [])), styles["Mono"]))
    story.append(Paragraph("dmesg Flags:", styles["Heading2"]))
    story.append(Preformatted("\n".join(krn.get("dmesg_flags", [])), styles["Mono"]))
    story.append(PageBreak())

    # Network
    net = analysis["network"]
    add_heading("Network", 1)
    story.append(Paragraph(f"Listeners: {len(net['listeners'])} | New: {len(net['new_listeners'])}", styles["BodyText"]))
    story.append(Paragraph("Routes:", styles["Heading2"]))
    story.append(Preformatted(net.get("routes", ""), styles["Mono"]))
    story.append(Paragraph("Interfaces:", styles["Heading2"]))
    story.append(Preformatted(net.get("interfaces", ""), styles["Mono"]))
    story.append(PageBreak())

    # Privilege Escalation
    pe = analysis["privilege_escalation"]
    add_heading("Privilege Escalation", 1)
    story.append(Paragraph("sudo -l:", styles["Heading2"]))
    story.append(Preformatted(pe.get("sudo_raw", ""), styles["Mono"]))
    story.append(Paragraph("NOPASSWD:", styles["Heading2"]))
    story.append(Preformatted("\n".join(pe.get("sudo_nopasswd", [])), styles["Mono"]))
    story.append(Paragraph("PATH Issues:", styles["Heading2"]))
    story.append(Preformatted("\n".join(pe.get("path_issues", [])), styles["Mono"]))
    story.append(Paragraph("Writable PATH:", styles["Heading2"]))
    story.append(Preformatted("\n".join(pe.get("path_writable", [])), styles["Mono"]))
    story.append(Paragraph("Risky Environment Vars:", styles["Heading2"]))
    story.append(Preformatted("\n".join(pe.get("env_risky", [])), styles["Mono"]))
    story.append(Paragraph("Exploitable SUID:", styles["Heading2"]))
    ex_lines = [f"{e['path']} -> {e['note']}" for e in pe.get("exploitable_suid", [])]
    story.append(Preformatted("\n".join(ex_lines), styles["Mono"]))
    story.append(Paragraph("Modprobe Hijack:", styles["Heading2"]))
    story.append(Preformatted("\n".join(pe.get("modprobe_hijack", [])), styles["Mono"]))
    story.append(Paragraph("Containers:", styles["Heading2"]))
    story.append(Preformatted("\n".join(pe.get("containers", [])), styles["Mono"]))
    story.append(PageBreak())

    # CVE
    cve = analysis["cve"]
    add_heading("CVE Matches", 1)
    if cve.get("matches"):
        cve_lines = [
            f"{m['product']} {m['version']} -> {m['cve']} (CVSS {m['cvss']}) {m['summary']}"
            for m in cve["matches"]
        ]
    else:
        cve_lines = ["No local CVE matches found."]
    story.append(Preformatted("\n".join(cve_lines), styles["Mono"]))
    story.append(PageBreak())

    # Score
    score = analysis["score"]
    add_heading("Security Score", 1)
    story.append(Paragraph(f"Score: {score['value']}/100", styles["Heading2"]))
    story.append(Paragraph("Deductions:", styles["Heading2"]))
    story.append(Preformatted("\n".join(score.get("deductions", [])), styles["Mono"]))
    story.append(Paragraph("Severity Counts:", styles["Heading2"]))
    sev_lines = [f"{k}: {v}" for k, v in score.get("severity_counts", {}).items()]
    story.append(Preformatted("\n".join(sev_lines), styles["Mono"]))
    story.append(Paragraph("Assessment:", styles["Heading2"]))
    story.append(Preformatted(score.get("assessment", ""), styles["Mono"]))
    story.append(PageBreak())

    # Charts
    add_heading("Charts", 1)
    for title, bio in charts.items():
        story.append(Paragraph(title, styles["Heading2"]))
        from reportlab.platypus import Image
        try:
            img = Image(bio, width=480, height=240)
        except Exception:
            img = Image(bio)
        story.append(img)
        story.append(Spacer(1, 12))

    # TOC handler
    def after_flowable(flowable):
        from reportlab.platypus.paragraph import Paragraph as RLParagraph
        if isinstance(flowable, RLParagraph):
            txt = flowable.getPlainText()
            style_name = flowable.style.name
            if style_name.startswith("Heading1"):
                toc.addEntry(0, txt, doc.canv.getPageNumber())
            elif style_name.startswith("Heading2"):
                toc.addEntry(1, txt, doc.canv.getPageNumber())

    doc.afterFlowable = after_flowable

    try:
        doc.build(story)
        return True, "PDF generated"
    except Exception as e:
        return False, f"PDF generation failed: {e}"
