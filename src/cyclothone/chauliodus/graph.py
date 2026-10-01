from __future__ import annotations

import logging
from collections import deque
from uuid import UUID

from cyclothone.storage.supabase_client import supabase

logger = logging.getLogger(__name__)


class EntityGraph:
    MAX_DEPTH = 3
    MIN_WEIGHT = 0.3

    def __init__(self, tenant_id: UUID) -> None:
        self.tenant_id = tenant_id

    async def neighbors(self, entity_id: UUID, relation: str | None = None, limit: int = 200) -> list[dict]:
        async def _do():
            client = await supabase._ensure()
            q = (client.table("chauliodus_edges").select(
                "id,source_id,target_id,relation,weight,confidence,evidence_count"
            ).eq("tenant_id", str(self.tenant_id)).eq("source_id", str(entity_id))
                 .gte("weight", self.MIN_WEIGHT).order("weight", desc=True).limit(limit))
            if relation:
                q = q.eq("relation", relation)
            return await q.execute()
        try:
            resp = await supabase._retry(_do)
            return list(resp.data or [])
        except Exception as exc:
            logger.warning("neighbors failed: %s", exc)
            return []

    async def breadth_first(self, root: UUID, max_depth: int | None = None) -> dict:
        depth = min(max_depth or self.MAX_DEPTH, self.MAX_DEPTH)
        seen: set[str] = {str(root)}
        edges: dict[str, dict] = {}
        frontier = deque([(str(root), 0)])
        while frontier:
            node, d = frontier.popleft()
            if d >= depth:
                continue
            for edge in await self.neighbors(UUID(node)):
                edges[edge["id"]] = edge
                nxt = edge["target_id"]
                if nxt not in seen:
                    seen.add(nxt)
                    frontier.append((nxt, d + 1))
        return {"root": str(root), "nodes": list(seen), "edges": list(edges.values())}

    async def cluster_score(self, entity_ids: list[UUID]) -> float:
        if len(entity_ids) < 2:
            return 0.0
        ids = [str(e) for e in entity_ids]
        async def _do():
            client = await supabase._ensure()
            return await (client.table("chauliodus_edges").select("weight,evidence_count")
                .eq("tenant_id", str(self.tenant_id)).in_("source_id", ids).in_("target_id", ids).execute())
        try:
            resp = await supabase._retry(_do)
        except Exception:
            return 0.0
        edges = resp.data or []
        if not edges:
            return 0.0
        import math
        max_possible = len(entity_ids) * (len(entity_ids) - 1)
        density = len(edges) / max_possible
        avg_weight = sum(float(e["weight"]) for e in edges) / len(edges)
        avg_evidence = sum(int(e["evidence_count"]) for e in edges) / len(edges)
        evidence_factor = min(1.0, math.log1p(avg_evidence) / math.log(20))
        return round(min(0.4 * density + 0.4 * avg_weight + 0.2 * evidence_factor, 1.0), 4)
