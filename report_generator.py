"""
report_generator.py - Export forensic reports in CSV, JSON, PDF
Universal Browser Forensic Investigation Suite
"""

import csv
import json
import socket
import os
from pathlib import Path
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

TOOL_VERSION = "1.0.0"


def _meta() -> dict:
    return {
        "tool": "Universal Browser Forensic Investigation Suite",
        "version": TOOL_VERSION,
        "scan_time": datetime.utcnow().isoformat() + "Z",
        "hostname": socket.gethostname(),
        "username": os.environ.get("USERNAME", os.environ.get("USER", "unknown")),
    }


def export_csv(records: list, output_path: Path, section: str = "history"):
    if not records:
        logger.warning("No records to export.")
        return
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=records[0].keys())
        writer.writeheader()
        writer.writerows(records)
    logger.info(f"CSV exported: {output_path}")


def export_json(data: dict, output_path: Path):
    payload = {"meta": _meta(), "data": data}
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    logger.info(f"JSON exported: {output_path}")


def export_pdf(data: dict, output_path: Path, evidence_hashes: dict = None):
    """Generate a basic PDF report using reportlab if available, else plain text."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet

        doc = SimpleDocTemplate(str(output_path), pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        meta = _meta()

        story.append(Paragraph("Universal Browser Forensic Investigation Suite", styles["Title"]))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"Scan Time: {meta['scan_time']}", styles["Normal"]))
        story.append(Paragraph(f"Hostname: {meta['hostname']}", styles["Normal"]))
        story.append(Paragraph(f"Username: {meta['username']}", styles["Normal"]))
        story.append(Paragraph(f"Tool Version: {meta['version']}", styles["Normal"]))
        story.append(Spacer(1, 12))

        if evidence_hashes:
            story.append(Paragraph("Evidence Hashes (SHA-256)", styles["Heading2"]))
            for fname, h in evidence_hashes.items():
                story.append(Paragraph(f"{fname}: {h}", styles["Normal"]))
            story.append(Spacer(1, 12))

        for section, records in data.items():
            if not records:
                continue
            story.append(Paragraph(section.upper(), styles["Heading2"]))
            if isinstance(records, list) and records:
                keys = list(records[0].keys())[:6]  # Limit columns
                table_data = [keys] + [[str(r.get(k, "")) for k in keys] for r in records[:200]]
                t = Table(table_data)
                t.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.black),
                ]))
                story.append(t)
                story.append(Spacer(1, 12))

        doc.build(story)
        logger.info(f"PDF exported: {output_path}")

    except ImportError:
        # Fallback to plain text
        with open(output_path.with_suffix(".txt"), "w", encoding="utf-8") as f:
            meta = _meta()
            f.write("Universal Browser Forensic Investigation Suite\n")
            f.write("=" * 60 + "\n")
            f.write(f"Scan Time: {meta['scan_time']}\n")
            f.write(f"Hostname: {meta['hostname']}\n")
            f.write(f"Username: {meta['username']}\n\n")
            for section, records in data.items():
                f.write(f"\n=== {section.upper()} ===\n")
                if isinstance(records, list):
                    for r in records[:500]:
                        f.write(str(r) + "\n")
        logger.info(f"Plain text report exported (reportlab not available)")
