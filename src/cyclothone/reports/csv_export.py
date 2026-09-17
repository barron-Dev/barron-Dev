from __future__ import annotations

import csv
import io

from sentinel.reports.models import ReportIR


def render_csv(report: ReportIR) -> bytes:
    buf = io.StringIO(newline="")
    writer = csv.writer(buf)
    writer.writerow(["case_number", report.case_number])
    writer.writerow(["title", report.title])
    writer.writerow(["category", report.category])
    writer.writerow(["severity", report.severity])
    writer.writerow(["status", report.status])
    writer.writerow(["created_at", report.created_at.isoformat()])
    writer.writerow(["financial_loss", report.financial_loss if report.financial_loss is not None else ""])
    writer.writerow(["currency", report.currency or ""])
    writer.writerow([])
    writer.writerow(["ioc_type", "value", "severity", "confidence", "source"])
    for ioc in report.iocs:
        writer.writerow([ioc.get("ioc_type", ""), ioc.get("value", ""), ioc.get("severity", ""), ioc.get("confidence", ""), ioc.get("source", "")])
    writer.writerow([])
    writer.writerow(["wallet"])
    for wallet in report.wallets:
        writer.writerow([wallet])
    writer.writerow([])
    writer.writerow(["ts", "kind", "actor", "payload"])
    for event in report.timeline:
        writer.writerow([event.get("ts", ""), event.get("kind", ""), event.get("actor", ""), event.get("payload", {})])
    return buf.getvalue().encode("utf-8-sig")
