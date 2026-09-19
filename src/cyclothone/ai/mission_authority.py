from __future__ import annotations

from uuid import UUID

from cyclothone.ai.envelope_issuer import MissionAuthority
from cyclothone.storage.supabase_client import supabase


class SupabaseMissionAuthority(MissionAuthority):
    """Resolve only an active, tenant-owned, hash-exact compiled Mission."""

    async def resolve(
        self,
        *,
        tenant_id: UUID,
        mission_id: str,
        version: int,
        compiled_hash: str,
    ) -> dict | None:
        if not mission_id or version < 1 or len(compiled_hash) != 64:
            return None

        async def do():
            client = await supabase._ensure()
            return await client.rpc(
                "resolve_ai_mission_binding",
                {
                    "p_tenant_id": str(tenant_id),
                    "p_mission_id": mission_id,
                    "p_version": version,
                    "p_compiled_hash": compiled_hash,
                },
            ).execute()

        response = await supabase._retry(do, attempts=2)
        rows = response.data or []
        if isinstance(rows, dict):
            rows = [rows]
        return rows[0] if rows else None
