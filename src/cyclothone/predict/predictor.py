from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Mapping
from uuid import UUID

RELATION_LIKELIHOOD: dict[str, float] = {
    "runs_on": 0.95, "hosts": 0.90, "connects_to": 0.75, "executes": 0.85,
    "authenticates": 0.80, "depends_on": 0.70, "manages": 0.75,
    "owns": 0.60, "trusts": 0.55, "reads": 0.40, "writes": 0.50,
}

@dataclass(frozen=True)
class TargetCandidate:
    node_id: str
    node_external: str
    node_type: str
    hops: int
    prior_score: float
    likelihood: float
    impact: float
    combined: float
    path: list[dict[str, Any]] = field(default_factory=list)

class PredictionInputError(ValueError):
    pass

class AttackPathPredictor:
    MAX_HORIZON = 5
    MAX_TOP_N = 100
    MIN_COMBINED = 0.05

    def __init__(self, graph: Any, historical_priors: Mapping[str, float] | None = None) -> None:
        self.graph = graph
        self.priors = {
            str(k): self._unit(v, "prior") for k, v in (historical_priors or {}).items()
        }

    @staticmethod
    def _unit(value: Any, name: str) -> float:
        try:
            result = float(value)
        except (TypeError, ValueError) as exc:
            raise PredictionInputError(f"{name} must be numeric") from exc
        if result != result or result in (float("inf"), float("-inf")) or not 0 <= result <= 1:
            raise PredictionInputError(f"{name} must be finite and between 0 and 1")
        return result

    @staticmethod
    def _node(graph: Any, node_id: str) -> Any | None:
        try:
            return graph.node(UUID(node_id))
        except (ValueError, TypeError):
            return None

    def predict(self, root_id: str, horizon: int = 3, top_n: int = 20) -> list[TargetCandidate]:
        try:
            root = str(UUID(root_id))
        except (ValueError, TypeError) as exc:
            raise PredictionInputError("root_id must be a UUID") from exc
        if not 1 <= horizon <= self.MAX_HORIZON:
            raise PredictionInputError("horizon must be between 1 and 5")
        if not 1 <= top_n <= self.MAX_TOP_N:
            raise PredictionInputError("top_n must be between 1 and 100")
        root_node = self._node(self.graph, root)
        if root_node is None:
            raise PredictionInputError("root node not found")
        # Validate the root even when it has no outgoing edges; invalid graph
        # inputs must not bypass validation merely because no candidate is reached.
        self._unit(getattr(root_node, "criticality", 0.0), "criticality")

        # Keep the maximum path likelihood per node. The visited map also prevents
        # cycles from expanding indefinitely while allowing a later stronger path.
        best: dict[str, tuple[float, list[dict[str, Any]]]] = {root: (1.0, [])}
        depth: dict[str, int] = {root: 0}
        queue: deque[str] = deque([root])

        while queue:
            current = queue.popleft()
            current_score, current_path = best[current]
            current_depth = depth[current]
            if current_depth >= horizon:
                continue

            for edge in self.graph.neighbors(current):
                next_id = str(edge.target_id)
                if next_id == root:
                    continue
                try:
                    edge_weight = self._unit(getattr(edge, "weight", 1.0), "edge weight")
                except PredictionInputError:
                    continue
                relation = str(getattr(edge, "relation", "unknown"))
                multiplier = RELATION_LIKELIHOOD.get(relation, 0.5)
                score = current_score * multiplier * edge_weight * 0.9
                next_depth = current_depth + 1
                previous = best.get(next_id)
                if previous is not None and previous[0] >= score and depth[next_id] <= next_depth:
                    continue
                best[next_id] = (score, current_path + [{
                    "from": current, "to": next_id, "relation": relation,
                    "weight": round(multiplier, 3),
                }])
                depth[next_id] = next_depth
                queue.append(next_id)

        candidates: list[TargetCandidate] = []
        for node_id, (likelihood_raw, path) in best.items():
            if node_id == root:
                continue
            node = self._node(self.graph, node_id)
            if node is None:
                continue
            node_type = str(getattr(node, "node_type", "unknown"))
            prior = self.priors.get(node_type, 0.5)
            impact = self._unit(getattr(node, "criticality", 0.0), "criticality")
            likelihood = max(0.0, min(1.0, likelihood_raw))
            combined = self._combine(prior, likelihood, impact)
            if combined < self.MIN_COMBINED:
                continue
            external = str(getattr(node, "external_id", node_id))
            candidates.append(TargetCandidate(
                node_id=node_id, node_external=external, node_type=node_type,
                hops=len(path), prior_score=round(prior, 4),
                likelihood=round(likelihood, 4), impact=round(impact, 4),
                combined=combined, path=path,
            ))
        candidates.sort(key=lambda c: (-c.combined, c.hops, c.node_id))
        return candidates[:top_n]

    @staticmethod
    def _combine(prior: float, likelihood: float, impact: float) -> float:
        if min(prior, likelihood, impact) <= 0:
            return 0.0
        return round(min((prior * likelihood * impact) ** (1 / 3), 1.0), 4)
