from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Iterator
from uuid import UUID


@dataclass(frozen=True, slots=True)
class TwinNode:
    id: UUID
    node_type: str
    external_id: str
    criticality: float
    attributes: dict


@dataclass(frozen=True, slots=True)
class TwinEdge:
    source_id: UUID
    target_id: UUID
    relation: str
    weight: float
    criticality: float


class TwinGraph:
    """Bounded, tenant-local graph with deterministic traversal order."""

    def __init__(self, *, max_nodes: int = 100_000, max_edges: int = 500_000) -> None:
        self._nodes: dict[UUID, TwinNode] = {}
        self._out: dict[UUID, list[TwinEdge]] = defaultdict(list)
        self.max_nodes = max_nodes
        self.max_edges = max_edges
        self._edge_count = 0

    def add_node(self, node: TwinNode) -> None:
        if node.id not in self._nodes and len(self._nodes) >= self.max_nodes:
            raise ValueError("digital twin node limit exceeded")
        if not 0 <= node.criticality <= 1:
            raise ValueError("node criticality must be between 0 and 1")
        self._nodes[node.id] = node

    def add_edge(self, edge: TwinEdge) -> None:
        if self._edge_count >= self.max_edges:
            raise ValueError("digital twin edge limit exceeded")
        if edge.source_id not in self._nodes or edge.target_id not in self._nodes:
            raise ValueError("edge references unknown node")
        if edge.source_id == edge.target_id:
            raise ValueError("self edges are not allowed")
        if not 0 <= edge.criticality <= 1 or not 0 <= edge.weight <= 10:
            raise ValueError("edge values out of range")
        self._out[edge.source_id].append(edge)
        self._edge_count += 1

    def finalize(self) -> None:
        for edges in self._out.values():
            edges.sort(key=lambda e: (e.target_id.hex, e.relation, -e.weight))

    def node(self, node_id: UUID) -> TwinNode | None:
        return self._nodes.get(node_id)

    def find_by_external(self, external_id: str) -> list[TwinNode]:
        value = external_id.strip()
        return sorted(
            (n for n in self._nodes.values() if n.external_id == value),
            key=lambda n: (n.node_type, n.id.hex),
        )

    def neighbors(self, node_id: UUID) -> Iterator[TwinEdge]:
        yield from self._out.get(node_id, ())

    def node_count(self) -> int:
        return len(self._nodes)

    def edge_count(self) -> int:
        return self._edge_count


class CascadeSimulator:
    """Deterministic bounded cascade model. It never executes an action."""

    PROPAGATION = {
        "runs": 0.90, "runs_on": 0.95, "connects_to": 0.60,
        "reads": 0.40, "writes": 0.50, "executes": 0.85,
        "authenticates": 0.75, "owns": 0.70, "depends_on": 0.80,
        "hosts": 0.95, "manages": 0.70, "trusts": 0.55, "controls": 0.85,
    }

    ACTION_FACTOR = {
        "isolate_host": 0.85, "kill_process": 0.95, "quarantine_file": 0.90,
        "disable_account": 0.80, "force_logout": 0.70, "block_hash": 0.65,
        "block_ip": 0.60,
    }

    def __init__(self, graph: TwinGraph) -> None:
        self.graph = graph

    def simulate(
        self, root_id: UUID, *, action: str, threshold: float = 0.15,
        max_depth: int = 6, max_affected: int = 500,
    ) -> dict:
        if action not in self.ACTION_FACTOR:
            raise ValueError("unsupported simulation action")
        if not 0 < threshold <= 1:
            raise ValueError("threshold must be in (0, 1]")
        if not 1 <= max_depth <= 16 or not 1 <= max_affected <= 5000:
            raise ValueError("simulation bounds out of range")
        if self.graph.node(root_id) is None:
            raise ValueError("root node not found")

        visited: dict[UUID, float] = {root_id: 1.0}
        queue: deque[tuple[UUID, float, int]] = deque([(root_id, 1.0, 0)])
        affected: list[dict] = []
        action_factor = self.ACTION_FACTOR[action]

        while queue and len(affected) < max_affected:
            current, score, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for edge in self.graph.neighbors(current):
                next_score = score * action_factor * self.PROPAGATION.get(edge.relation, 0.5) * edge.weight
                next_score = min(next_score, 1.0)
                if next_score < threshold or next_score <= visited.get(edge.target_id, 0.0):
                    continue
                node = self.graph.node(edge.target_id)
                if node is None:
                    continue
                visited[edge.target_id] = next_score
                affected.append({
                    "node_id": str(node.id), "node_type": node.node_type,
                    "external_id": node.external_id, "impact": round(next_score, 4),
                    "depth": depth + 1, "relation": edge.relation,
                    "criticality": round(node.criticality, 4),
                })
                queue.append((edge.target_id, next_score, depth + 1))
                if len(affected) >= max_affected:
                    break

        affected.sort(key=lambda x: (-x["impact"], x["depth"], x["node_id"]))
        critical = [a for a in affected if a["criticality"] >= 0.7 and a["impact"] >= 0.4]
        aggregate = sum(a["impact"] * a["criticality"] for a in affected)
        impact_score = round(min(aggregate / max(self.graph.node_count(), 1), 1.0), 4)

        return {
            "root_id": str(root_id), "affected": affected,
            "critical_impact": critical, "cascade_size": len(affected),
            "impact_score": impact_score, "truncated": bool(queue),
        }
