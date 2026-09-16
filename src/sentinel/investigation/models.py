from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID


STATUSES = {"requested", "approved", "running", "completed", "cancelled", "failed"}
EVIDENCE_TYPES = {"network", "dns", "process", "file", "browser", "screenshot", "indicator", "provider_record", "other"}


@dataclass(frozen=True, slots=True)
class InvestigationRequest:
    tenant_id: UUID
    purpose: str
    authorization_ref: str
    provider: str
    case_id: UUID | None = None
    created_by: UUID | None = None

    def __post_init__(self) -> None:
        if not self.purpose.strip() or len(self.purpose) > 500:
            raise ValueError("purpose must be between 1 and 500 characters")
        if not self.authorization_ref.strip() or len(self.authorization_ref) > 500:
            raise ValueError("authorization_ref must be between 1 and 500 characters")
        if not self.provider.strip() or len(self.provider) > 120:
            raise ValueError("provider must be between 1 and 120 characters")


@dataclass(frozen=True, slots=True)
class InvestigationEvidence:
    session_id: UUID
    tenant_id: UUID
    evidence_type: str
    sha256: str
    object_ref: str
    collected_at: datetime
    metadata: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.evidence_type not in EVIDENCE_TYPES:
            raise ValueError("unsupported evidence_type")
        if len(self.sha256) != 64 or any(c not in "0123456789abcdef" for c in self.sha256.lower()):
            raise ValueError("sha256 must be a 64-character hexadecimal digest")
        if not self.object_ref.strip():
            raise ValueError("object_ref is required")
