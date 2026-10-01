from __future__ import annotations

import hashlib
import json
from uuid import UUID

from cyclothone.ai.envelope_issuer import ProviderBinding
from cyclothone.storage.supabase_client import supabase


class SupabaseProviderBinding(ProviderBinding):
    """Resolve only explicitly provisioned tenant/model/provider authority."""

    async def resolve(
        self,
        *,
        tenant_id: UUID,
        agent_id: UUID,
        model_id: str,
        provider_id: str,
    ) -> dict | None:
        async def do():
            client = await supabase._ensure()
            return await client.rpc(
                "resolve_ai_provider_binding",
                {
                    "p_tenant_id": str(tenant_id),
                    "p_agent_id": str(agent_id),
                    "p_model_id": model_id,
                    "p_provider_id": provider_id,
                },
            ).execute()

        response = await supabase._retry(do, attempts=2)
        rows = response.data or []
        if isinstance(rows, dict):
            rows = [rows]
        return rows[0] if rows else None


def provider_binding_hash(*, model_id: str, provider_id: str, authority_version: str = "1") -> str:
    payload = {
        "model_id": model_id,
        "provider_id": provider_id,
        "authority_version": authority_version,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()
