from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

from cyclothone.investigation.models import InvestigationEvidence, InvestigationRequest
from cyclothone.storage.supabase_client import supabase


class AuthorizedForensicsProvider(Protocol):
    """Adapter contract for a legally authorized remote-forensics provider."""

    async def start(self, request: InvestigationRequest) -> str: ...
    async def stop(self, provider_session_id: str) -> None: ...


class InvestigationControlPlane:
    def __init__(self, providers: dict[str, AuthorizedForensicsProvider] | None = None) -> None:
        self.providers = providers or {}

    async def request(self, request: InvestigationRequest) -> dict[str, Any]:
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
        claimed = await supabase.rpc(
            "claim_investigation_start",
            {"p_session_id": str(session_id), "p_tenant_id": str(tenant_id)},
        )
        if isinstance(claimed, list):
            row = claimed[0] if claimed else None
        elif isinstance(claimed, dict):
            row = claimed
        else:
            row = None
        if row is None:
            existing = await self._get(session_id, tenant_id)
            if existing is None:
                raise LookupError("investigation session not found")
            raise ValueError("investigation session is not awaiting approval")

        provider = self.providers.get(str(row["provider"]))
        if provider is None:
            await self._mark_failed(session_id, tenant_id, "investigation provider is not configured")
            raise ValueError("investigation provider is not configured")

        request = InvestigationRequest(
            tenant_id=tenant_id,
            case_id=UUID(str(row["case_id"])) if row.get("case_id") else None,
            created_by=UUID(str(row["created_by"])) if row.get("created_by") else None,
            purpose=str(row["purpose"]),
            authorization_ref=str(row["authorization_ref"]),
            provider=str(row["provider"]),
        )
        try:
            provider_session_id = await provider.start(request)
        except Exception as exc:
            await self._mark_failed(session_id, tenant_id, str(exc))
            raise

        now = datetime.now(UTC).isoformat()
        updated = await supabase.update(
            "investigation_sessions",
            {"status": "running", "provider_session_id": provider_session_id, "started_at": now, "updated_at": now},
            id=str(session_id), tenant_id=str(tenant_id), status="approved",
        )
        if updated is None:
            try:
                await provider.stop(provider_session_id)
            finally:
                await self._mark_failed(session_id, tenant_id, "failed to persist running investigation session")
            raise RuntimeError("failed to persist running investigation session")

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
            id=str(session_id), tenant_id=str(tenant_id), status="running",
        )
        if result is None:
            raise ValueError("investigation session is not running")
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

    async def _mark_failed(self, session_id: UUID, tenant_id: UUID, reason: str) -> None:
        now = datetime.now(UTC).isoformat()
        await supabase.update(
            "investigation_sessions",
            {"status": "failed", "updated_at": now},
            id=str(session_id), tenant_id=str(tenant_id), status="approved",
        )
        await self._event(session_id, tenant_id, "failed", {"reason": reason[:1000]})

    async def _get(self, session_id: UUID, tenant_id: UUID) -> dict[str, Any] | None:
        return await supabase.select_one(
            "investigation_sessions",
            "id,tenant_id,case_id,created_by,purpose,authorization_ref,status,provider,provider_session_id,started_at,completed_at",
            id=str(session_id), tenant_id=str(tenant_id),
        )

    async def _event(self, session_id: UUID, tenant_id: UUID, event_type: str, payload: dict[str, Any]) -> None:
        await supabase.insert_one(
            "investigation_events",
            {"tenant_id": str(tenant_id), "session_id": str(session_id), "event_type": event_type, "actor": "cyclothone", "payload": payload},
        )
