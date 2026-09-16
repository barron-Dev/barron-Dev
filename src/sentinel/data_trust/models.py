from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

CLASSIFICATIONS = {"public", "internal", "confidential", "restricted", "regulated"}
DESTINATIONS = {"endpoint", "usb", "bluetooth", "cloud", "browser", "network", "email", "messaging", "unknown"}
DEVICE_TRUST = {"managed", "compliant", "trusted", "unknown", "blocked"}

@dataclass(frozen=True, slots=True)
class TransferRequest:
    tenant_id: UUID
    asset_id: UUID | None
    device_id: UUID | None
    actor_id: UUID | None
    source_type: str
    destination_type: str
    destination_ref: str | None
    destination_trust: str
    bytes_transferred: int
    content_inspected: bool
    content_hash: str | None
    observed_at: datetime
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.source_type not in {"endpoint", "browser", "cloud", "mobile", "server", "unknown"}:
            raise ValueError("invalid source_type")
        if self.destination_type not in DESTINATIONS:
            raise ValueError("invalid destination_type")
        if self.destination_trust not in DEVICE_TRUST:
            raise ValueError("invalid destination_trust")
        if self.bytes_transferred < 0:
            raise ValueError("bytes_transferred must be non-negative")
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        if self.content_hash is not None and len(self.content_hash) != 64:
            raise ValueError("content_hash must be SHA-256")

@dataclass(frozen=True, slots=True)
class TransferDecision:
    decision: str
    reason_codes: tuple[str, ...]
    policy_id: UUID | None
    classification: str | None

    def __post_init__(self) -> None:
        if self.decision not in {"allow", "block", "quarantine", "review"}:
            raise ValueError("invalid transfer decision")
