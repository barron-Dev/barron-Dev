from __future__ import annotations

import io
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from cyclothone.reports.models import ReportIR


def render_pdf(report: ReportIR) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=18 * mm, bottomMargin=18 * mm, title=f"{report.case_number} - {report.title}", author=report.tenant_name)
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("SentinelH1", parent=styles["Heading1"], fontSize=18, spaceAfter=6)
    h2 = ParagraphStyle("SentinelH2", parent=styles["Heading2"], fontSize=13, spaceBefore=10, spaceAfter=5)
    body = ParagraphStyle("SentinelBody", parent=styles["BodyText"], fontSize=9.5, leading=13)
    small = ParagraphStyle("SentinelSmall", parent=body, fontSize=7.5)
    story: list[object] = [Paragraph(escape(report.case_number), small), Paragraph(escape(report.title), h1), Paragraph(f"Agency: <b>{escape(report.agency)}</b> &nbsp; Severity: <b>{escape(report.severity)}</b> &nbsp; Status: <b>{escape(report.status)}</b>", body), Spacer(1, 5 * mm)]
    if report.summary:
        story += [Paragraph("Summary", h2), Paragraph(escape(report.summary).replace("\n", "<br/>"), body)]
    if report.financial_loss is not None:
        story += [Paragraph("Financial impact", h2), Paragraph(f"{escape(report.currency or '')} {report.financial_loss:,.2f}".strip(), body)]
    if report.iocs:
        story.append(Paragraph("Indicators of Compromise", h2))
        rows = [["Type", "Value", "Severity", "Confidence", "Source"]]
        for ioc in report.iocs[:500]:
            rows.append([str(ioc.get("ioc_type", "")), Paragraph(escape(str(ioc.get("value", ""))), small), str(ioc.get("severity", "")), str(ioc.get("confidence", "")), str(ioc.get("source", ""))])
        table = Table(rows, colWidths=[24 * mm, 88 * mm, 22 * mm, 24 * mm, 22 * mm], repeatRows=1)
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 7), ("GRID", (0, 0), (-1, -1), 0.25, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(table)
    if report.wallets:
        story += [Paragraph("Cryptocurrency wallets", h2)] + [Paragraph(escape(w), small) for w in report.wallets[:500]]
    if report.timeline:
        story.append(Paragraph("Timeline", h2))
        rows = [["Timestamp", "Kind", "Actor", "Detail"]]
        for event in report.timeline[:500]:
            payload = event.get("payload") or {}
            detail = ", ".join(f"{k}={v}" for k, v in list(payload.items())[:6])
            rows.append([str(event.get("ts", ""))[:19].replace("T", " "), str(event.get("kind", "")), str(event.get("actor", ""))[:40], Paragraph(escape(detail)[:800], small)])
        table = Table(rows, colWidths=[34 * mm, 28 * mm, 42 * mm, 76 * mm], repeatRows=1)
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 7), ("GRID", (0, 0), (-1, -1), 0.25, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(table)
    if report.actions:
        story.append(Paragraph("Response actions", h2))
        rows = [["Timestamp", "Action", "Status", "Issued by"]]
        for action in report.actions[:500]:
            rows.append([str(action.get("created_at", ""))[:19].replace("T", " "), str(action.get("action", "")), str(action.get("status", "")), str(action.get("issued_by", ""))])
        table = Table(rows, colWidths=[40 * mm, 45 * mm, 30 * mm, 65 * mm], repeatRows=1)
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 7), ("GRID", (0, 0), (-1, -1), 0.25, colors.grey)]))
        story.append(table)
    doc.build(story)
    return buf.getvalue()
