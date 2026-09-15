from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Mapping
from uuid import UUID

ARTIFACT_TYPES = {
    "canary_token",
    "honeyfile",
    "fake_aws_key",
    "fake_browser_cookie",
    "fake_ssh_key",
    "fake_wallet_seed",
    "fake_admin_share",
    "fake_service_account",
}


@dataclass(frozen=True, slots=True)
class ArtifactSpec:
    tenant_id: UUID
    artifact_type: str
    name: str
    target: str
    metadata: Mapping[str, Any] = field(default_factory=dict)
    severity: str = "critical"
    created_by: UUID | None = None

    def __post_init__(self) -> None:
        if self.artifact_type not in ARTIFACT_TYPES:
            raise ValueError("unsupported deception artifact type")
        if not self.name.strip() or not self.target.strip():
            raise ValueError("artifact name and target are required")
        if self.severity not in {"medium", "high", "critical"}:
            raise ValueError("invalid deception severity")


@dataclass(frozen=True, slots=True)
class DeceptionArtifact:
    id: UUID
    tenant_id: UUID
    artifact_type: str
    name: str
    target: str
    token_prefix: str
    secret: str
    callback_url: str
    metadata: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class TriggerResult:
    trigger_id: UUID
    tenant_id: UUID
    artifact_id: UUID
    artifact_type: str
    severity: str
    observed_at: datetime
    evidence: Mapping[str, Any]

    def __post_init__(self) -> None:
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        if self.severity not in {"high", "critical"}:
            raise ValueError("deception triggers must be high or critical")


def utcnow() -> datetime:
    return datetime.now(UTC)
