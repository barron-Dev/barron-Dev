from __future__ import annotations

import io
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def render_evidence_pdf(tenant_name: str, framework_id: str, period_start: datetime, period_end: datetime, summary: dict, controls: list[dict], pack_sha256: str, signature: str) -> bytes:
    """Render an evidence/readiness report locally; it is not an auditor report."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=18 * mm, bottomMargin=18 * mm, title=f"{framework_id.upper()} Evidence - {tenant_name}", author="Sentinel Security Platform")
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("sentinel-h1", parent=styles["Heading1"], fontSize=18, spaceAfter=8)
    h2 = ParagraphStyle("sentinel-h2", parent=styles["Heading2"], fontSize=12, spaceBefore=10, spaceAfter=4)
    body = ParagraphStyle("sentinel-body", parent=styles["BodyText"], fontSize=9, leading=13)
    mono = ParagraphStyle("sentinel-mono", parent=body, fontName="Courier", fontSize=7)
    story = [Paragraph("Compliance Evidence & Readiness Report", h1), Paragraph(f"<b>{escape(tenant_name)}</b> - {escape(framework_id.upper())}", body), Paragraph(f"Period: {period_start.date()} to {period_end.date()} | Generated: {datetime.now().isoformat()}Z", body), Spacer(1, 6 * mm)]
    summary_rows = [["Readiness score", f"{float(summary.get('overall_score') or 0) * 100:.1f}%"], ["Controls", str(summary.get("total_controls") or 0)], ["Passing", str(summary.get("passing") or 0)], ["Partial", str(summary.get("partial") or 0)], ["Failing", str(summary.get("failing") or 0)], ["Unknown", str(summary.get("unknown") or 0)]]
    table = Table(summary_rows, colWidths=[60 * mm, 110 * mm])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f5f7fa")), ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 9), ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.extend([table, Spacer(1, 4 * mm), Paragraph("Integrity", h2), Paragraph("Pack SHA-256: " + escape(pack_sha256), mono), Paragraph("Ed25519 signature: " + escape(signature), mono), Paragraph("This document is generated evidence/readiness material and does not constitute an independent service auditor's report or attestation.", body), PageBreak(), Paragraph("Control Detail", h2)])
    rows = [["Code", "Control", "Category", "Status", "Score"]]
    for control in controls:
        rows.append([str(control.get("control_code", control.get("code", ""))), Paragraph(escape(str(control.get("title", ""))), body), str(control.get("category", "-")), str(control.get("status", "unknown")), f"{float(control.get('score') or 0) * 100:.0f}%"])
    controls_table = Table(rows, colWidths=[25 * mm, 68 * mm, 27 * mm, 25 * mm, 18 * mm], repeatRows=1)
    controls_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f5f7fa")), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 7.5), ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(controls_table)
    doc.build(story)
    return buf.getvalue()
