from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class ReportIR:
    case_number: str
    title: str
    category: str
    severity: str
    status: str
    created_at: datetime
    tenant_name: str
    agency: str
    summary: str
    timeline: list[dict[str, Any]] = field(default_factory=list)
    iocs: list[dict[str, Any]] = field(default_factory=list)
    wallets: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    actions: list[dict[str, Any]] = field(default_factory=list)
    financial_loss: float | None = None
    currency: str | None = None
    contact: dict[str, str] = field(default_factory=dict)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
