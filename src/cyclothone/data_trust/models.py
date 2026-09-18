from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from cyclothone.data_trust.channels import DESTINATION_TYPES, SOURCE_TYPES, normalize_destination, normalize_source

CLASSIFICATIONS = {"public", "internal", "confidential", "restricted", "regulated"}
DESTINATIONS = DESTINATION_TYPES
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
        source = normalize_source(self.source_type)
        destination = normalize_destination(self.destination_type)
        object.__setattr__(self, "source_type", source)
        object.__setattr__(self, "destination_type", destination)
        if self.destination_trust not in DEVICE_TRUST:
            raise ValueError("invalid destination_trust")
        if self.bytes_transferred < 0:
            raise ValueError("bytes_transferred must be non-negative")
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        if self.content_hash is not None:
            digest = self.content_hash.lower()
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("content_hash must be SHA-256")
            object.__setattr__(self, "content_hash", digest)


@dataclass(frozen=True, slots=True)
class TransferDecision:
    decision: str
    reason_codes: tuple[str, ...]
    policy_id: UUID | None
    classification: str | None
    event_id: UUID | None = None
    detection_id: UUID | None = None

    def __post_init__(self) -> None:
        if self.decision not in {"allow", "block", "quarantine", "review"}:
            raise ValueError("invalid transfer decision")
