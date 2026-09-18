from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from cyclothone.storage.supabase_client import supabase


@dataclass(frozen=True, slots=True)
class PeerReputation:
    peer_id: UUID
    reputation: float


class FederationReputation:
    """Server-side reputation adapter backed by atomic federation RPCs."""

    async def record_result(self, *, from_peer_id: UUID, to_peer_id: UUID, accepted: bool) -> None:
        await supabase.rpc(
            "record_fed_peer_result",
            {
                "p_from_peer": str(from_peer_id),
                "p_to_peer": str(to_peer_id),
                "p_accepted": accepted,
            },
        )

    async def recompute(self, *, peer_id: UUID) -> None:
        await supabase.rpc("recompute_peer_reputation", {"p_peer": str(peer_id)})

    async def record_poisoning(
        self,
        *,
        peer_id: UUID,
        ioc_hash: str,
        reason: str,
        reporter_tenant: UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        if len(ioc_hash) != 64 or any(c not in "0123456789abcdef" for c in ioc_hash):
            raise ValueError("ioc_hash must be lowercase SHA-256 hex")
        if reason not in {"false_positive", "targeted", "low_quality"}:
            raise ValueError("unsupported poisoning reason")
        await supabase.insert_one(
            "fed_poisoning_events",
            {
                "peer_id": str(peer_id),
                "ioc_hash": ioc_hash,
                "reason": reason,
                "reporter_tenant": str(reporter_tenant) if reporter_tenant else None,
                "details": details or {},
            },
        )
        await self.recompute(peer_id=peer_id)

    async def get(self, *, peer_id: UUID) -> PeerReputation | None:
        row = await supabase.select_one("federation_peers", "id,reputation", id=str(peer_id))
        if not row:
            return None
        return PeerReputation(peer_id=peer_id, reputation=float(row["reputation"]))
