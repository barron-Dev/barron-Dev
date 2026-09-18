from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from cyclothone.storage.supabase_client import supabase
from cyclothone.twin.graph import CascadeSimulator, TwinEdge, TwinGraph, TwinNode


class DigitalTwinService:
    """Loads one tenant graph, simulates an action, and durably records the result."""

    def __init__(self, tenant_id: UUID, user_id: UUID | None = None) -> None:
        self.tenant_id = tenant_id
        self.user_id = user_id
        self._graph: TwinGraph | None = None

    async def load(self) -> TwinGraph:
        graph = TwinGraph()

        async def _nodes():
            client = await supabase._ensure()
            return await client.table("twin_nodes").select(
                "id,node_type,external_id,criticality,attributes"
            ).eq("tenant_id", str(self.tenant_id)).limit(100000).execute()

        async def _edges():
            client = await supabase._ensure()
            return await client.table("twin_edges").select(
                "source_id,target_id,relation,weight,criticality"
            ).eq("tenant_id", str(self.tenant_id)).limit(500000).execute()

        nodes = await supabase._retry(_nodes)
        for row in nodes.data or []:
            graph.add_node(TwinNode(
                id=UUID(row["id"]), node_type=row["node_type"],
                external_id=row["external_id"], criticality=float(row["criticality"]),
                attributes=row.get("attributes") or {},
            ))

        edges = await supabase._retry(_edges)
        for row in edges.data or []:
            graph.add_edge(TwinEdge(
                source_id=UUID(row["source_id"]), target_id=UUID(row["target_id"]),
                relation=row["relation"], weight=float(row["weight"]),
                criticality=float(row["criticality"]),
            ))
        graph.finalize()
        self._graph = graph
        return graph

    async def simulate(self, target_external_id: str, action: str, args: dict | None = None) -> dict:
        target_external_id = target_external_id.strip()
        if not target_external_id:
            raise ValueError("target is required")
        if len(target_external_id) > 512:
            raise ValueError("target is too long")
        if args is not None and len(args) > 32:
            raise ValueError("too many simulation arguments")

        started = datetime.now(timezone.utc)
        graph = self._graph or await self.load()
        candidates = graph.find_by_external(target_external_id)
        if not candidates:
            raise ValueError("node not found")
        if len(candidates) > 1:
            raise ValueError("target is ambiguous; use a unique external identifier")
        target = candidates[0]

        result = CascadeSimulator(graph).simulate(
            target.id, action=action, threshold=0.15, max_depth=6, max_affected=500
        )
        recommendation = self._recommend(result)
        duration_ms = max(
            0, int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
        )

        async def _record():
            return await supabase.rpc("twin_record_simulation", {
                "p_tenant": str(self.tenant_id), "p_action": action,
                "p_target_node": str(target.id), "p_args": args or {},
                "p_requested_by": str(self.user_id) if self.user_id else None,
                "p_status": "complete", "p_impact_score": result["impact_score"],
                "p_cascade_size": result["cascade_size"],
                "p_affected_nodes": result["affected"][:500],
                "p_critical_impact": result["critical_impact"][:100],
                "p_recommendation": recommendation, "p_duration_ms": duration_ms,
            })

        # A result that cannot be durably audited is not reported as successful.
        simulation_id = await supabase._retry(_record, attempts=2)
        return {
            "simulation_id": simulation_id, "action": action,
            "target": target.external_id, "impact_score": result["impact_score"],
            "cascade_size": result["cascade_size"],
            "critical_impact": result["critical_impact"][:20],
            "recommendation": recommendation, "truncated": result["truncated"],
            "duration_ms": duration_ms,
        }

    @staticmethod
    def _recommend(result: dict) -> str:
        critical = len(result["critical_impact"])
        score = result["impact_score"]
        if critical:
            return f"REVIEW_REQUIRED: {critical} critical node(s) are in the simulated cascade."
        if score >= 0.7:
            return "REVIEW_REQUIRED: high modeled cascade impact."
        if score >= 0.4:
            return "CAUTION: moderate modeled cascade impact; validate scope before execution."
        return "LOW_MODELED_IMPACT: no material cascade above the configured threshold was identified."
