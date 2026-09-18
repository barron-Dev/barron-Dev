from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from uuid import UUID


@dataclass(frozen=True, slots=True)
class KGNode:
    id: str
    kind: str
    label: str
    summary: str | None
    service_id: str | None
    tags: tuple[str, ...] = ()
    priority: int = 100
    metadata: dict = field(default_factory=dict)


class KnowledgeGraph:
    """Bounded deterministic graph used for contextual relationships."""

    def __init__(self, *, max_nodes: int = 50_000, max_edges: int = 200_000) -> None:
        self.nodes: dict[str, KGNode] = {}
        self.out: dict[str, list[tuple[str, str, float]]] = {}
        self.max_nodes = max_nodes
        self.max_edges = max_edges
        self._edge_count = 0

    def add(self, node: KGNode) -> None:
        if node.id not in self.nodes and len(self.nodes) >= self.max_nodes:
            raise ValueError("knowledge graph node limit exceeded")
        if not node.id or len(node.id) > 160:
            raise ValueError("invalid knowledge node id")
        if not 0 <= node.priority <= 100_000:
            raise ValueError("knowledge node priority out of range")
        self.nodes[node.id] = node

    def link(self, src: str, dst: str, relation: str, weight: float = 1.0) -> None:
        if self._edge_count >= self.max_edges:
            raise ValueError("knowledge graph edge limit exceeded")
        if src not in self.nodes or dst not in self.nodes:
            raise ValueError("knowledge edge references unknown node")
        if src == dst:
            raise ValueError("knowledge self-edge is not allowed")
        if not 0 <= weight <= 10:
            raise ValueError("knowledge edge weight out of range")
        self.out.setdefault(src, []).append((dst, relation, float(weight)))
        self._edge_count += 1

    def finalize(self) -> None:
        for edges in self.out.values():
            edges.sort(key=lambda edge: (edge[1], edge[0], -edge[2]))

    def bfs(self, root: str, depth: int = 2, max_results: int = 500) -> list[tuple[str, int]]:
        if root not in self.nodes:
            return []
        if not 0 <= depth <= 8 or not 1 <= max_results <= 5000:
            raise ValueError("invalid graph traversal bounds")

        seen = {root}
        result: list[tuple[str, int]] = [(root, 0)]
        queue: deque[tuple[str, int]] = deque([(root, 0)])
        while queue and len(result) < max_results:
            current, distance = queue.popleft()
            if distance >= depth:
                continue
            for nxt, _, _ in self.out.get(current, ()):
                if nxt in seen:
                    continue
                seen.add(nxt)
                result.append((nxt, distance + 1))
                if len(result) >= max_results:
                    break
                queue.append((nxt, distance + 1))
        return result

    def related(self, node_id: str, depth: int = 2, max_results: int = 100) -> list[KGNode]:
        return [
            self.nodes[nid]
            for nid, _ in self.bfs(node_id, depth, max_results + 1)
            if nid != node_id and nid in self.nodes
        ][:max_results]
