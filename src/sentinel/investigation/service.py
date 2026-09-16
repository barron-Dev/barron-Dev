from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

from sentinel.investigation.models import InvestigationEvidence, InvestigationRequest
from sentinel.storage.supabase_client import supabase


class AuthorizedForensicsProvider(Protocol):
    """Adapter contract for a legally authorized remote-forensics provider.

    Implementations are intentionally external to Sentinel. A provider must
    enforce its own authorization, endpoint consent/legal authority, and audit
    controls before returning a provider session identifier.
    """

    async def start(self, request: InvestigationRequest) -> str: ...
    async def stop(self, provider_session_id: str) -> None: ...


class InvestigationControlPlane:
    def __init__(self, providers: dict[str, AuthorizedForensicsProvider] | None = None) -> None:
        self.providers = providers or {}

    async def request(self, request: InvestigationRequest) -> dict[str, Any]:
        if request.provider not in self.providers:
            raise ValueError("investigation provider is not configured")
        row = await supabase.insert_one(
            "investigation_sessions",
            {
                "tenant_id": str(request.tenant_id),
                "case_id": str(request.case_id) if request.case_id else None,
                "created_by": str(request.created_by) if request.created_by else None,
                "purpose": request.purpose,
                "authorization_ref": request.authorization_ref,
                "status": "requested",
                "provider": request.provider,
            },
        )
        session_id = UUID(str(row["id"]))
        return {"id": str(session_id), "status": "requested", "provider": request.provider}

    async def approve_and_start(self, session_id: UUID, tenant_id: UUID) -> dict[str, Any]:
        row = await self._get(session_id, tenant_id)
        if row is None:
            raise LookupError("investigation session not found")
        if row["status"] != "requested":
            raise ValueError("investigation session is not awaiting approval")
        provider = self.providers.get(str(row["provider"]))
        if provider is None:
            raise ValueError("investigation provider is not configured")

        request = InvestigationRequest(
            tenant_id=tenant_id,
            case_id=UUID(str(row["case_id"])) if row.get("case_id") else None,
            created_by=UUID(str(row["created_by"])) if row.get("created_by") else None,
            purpose=str(row["purpose"]),
            authorization_ref=str(row["authorization_ref"]),
            provider=str(row["provider"]),
        )
        provider_session_id = await provider.start(request)
        now = datetime.now(UTC).isoformat()
        updated = await supabase.update(
            "investigation_sessions",
            {"status": "running", "provider_session_id": provider_session_id, "started_at": now, "updated_at": now},
            id=str(session_id), tenant_id=str(tenant_id), status="requested",
        )
        await self._event(session_id, tenant_id, "started", {"provider": row["provider"]})
        return updated

    async def stop(self, session_id: UUID, tenant_id: UUID) -> dict[str, Any]:
        row = await self._get(session_id, tenant_id)
        if row is None:
            raise LookupError("investigation session not found")
        provider_session_id = row.get("provider_session_id")
        if provider_session_id:
            provider = self.providers.get(str(row["provider"]))
            if provider is None:
                raise ValueError("investigation provider is not configured")
            await provider.stop(str(provider_session_id))
        now = datetime.now(UTC).isoformat()
        result = await supabase.update(
            "investigation_sessions",
            {"status": "completed", "completed_at": now, "updated_at": now},
            id=str(session_id), tenant_id=str(tenant_id),
        )
        await self._event(session_id, tenant_id, "completed", {})
        return result

    async def record_evidence(self, evidence: InvestigationEvidence) -> dict[str, Any]:
        session = await self._get(evidence.session_id, evidence.tenant_id)
        if session is None:
            raise LookupError("investigation session not found")
        if session["status"] not in {"running", "completed"}:
            raise ValueError("evidence can only be recorded for an active or completed session")
        return await supabase.insert_one(
            "investigation_evidence",
            {
                "tenant_id": str(evidence.tenant_id),
                "session_id": str(evidence.session_id),
                "evidence_type": evidence.evidence_type,
                "sha256": evidence.sha256.lower(),
                "object_ref": evidence.object_ref,
                "collected_at": evidence.collected_at.isoformat(),
                "metadata": evidence.metadata,
            },
        )

    async def _get(self, session_id: UUID, tenant_id: UUID) -> dict[str, Any] | None:
        return await supabase.select_one(
            "investigation_sessions",
            "id,tenant_id,case_id,created_by,purpose,authorization_ref,status,provider,provider_session_id,started_at,completed_at",
            id=str(session_id), tenant_id=str(tenant_id),
        )

    async def _event(self, session_id: UUID, tenant_id: UUID, event_type: str, payload: dict[str, Any]) -> None:
        await supabase.insert_one(
            "investigation_events",
            {"tenant_id": str(tenant_id), "session_id": str(session_id), "event_type": event_type, "actor": "sentinel", "payload": payload},
        )
