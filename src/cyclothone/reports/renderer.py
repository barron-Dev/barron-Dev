from __future__ import annotations

import json
from dataclasses import asdict

from sentinel.reports.csv_export import render_csv
from sentinel.reports.models import ReportIR
from sentinel.reports.pdf import render_pdf
from sentinel.reports.stix import render_stix21

MIME = {"pdf": "application/pdf", "csv": "text/csv; charset=utf-8", "stix2.1": "application/stix+json", "json": "application/json"}


def render(report: ReportIR, fmt: str) -> tuple[bytes, str]:
    fmt = fmt.lower()
    if fmt == "pdf": return render_pdf(report), MIME[fmt]
    if fmt == "csv": return render_csv(report), MIME[fmt]
    if fmt in ("stix", "stix2.1"): return render_stix21(report), MIME["stix2.1"]
    if fmt == "json": return json.dumps(asdict(report), default=str, indent=2).encode(), MIME[fmt]
    raise ValueError(f"unsupported report format: {fmt}")
