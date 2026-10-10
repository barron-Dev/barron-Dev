from __future__ import annotations

from collections import defaultdict
from typing import Any


def build_actor_technique_bipartite_graph(actors: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a deterministic bipartite graph description for analyst inspection."""
    nodes: dict[str, dict[str, str]] = {}
    edges: set[tuple[str, str]] = set()
    for actor in actors:
        actor_id = str(actor.get("actor_id") or "").strip()
        if not actor_id:
            continue
        actor_node = f"actor:{actor_id}"
        nodes[actor_node] = {"kind": "actor", "label": str(actor.get("primary_name") or actor_id)[:200]}
        profile = actor.get("profile") or {}
        techniques = actor.get("attack_techniques") or profile.get("attack_techniques") or []
        for raw in techniques if isinstance(techniques, list) else []:
            technique = str(raw).strip().upper()
            if not technique.startswith("T") or len(technique) > 12:
                continue
            technique_node = f"technique:{technique}"
            nodes[technique_node] = {"kind": "technique", "label": technique}
            edges.add((actor_node, technique_node))
    return {"nodes": [{"id": k, **nodes[k]} for k in sorted(nodes)], "edges": [{"source": a, "target": b} for a, b in sorted(edges)], "algorithm": "bipartite-actor-technique-v1"}


def detect_communities(actors: list[dict[str, Any]]) -> dict[str, Any]:
    """Run Leiden when the real optional graph runtime is installed; never fake it."""
    graph = build_actor_technique_bipartite_graph(actors)
    try:
        import igraph as ig
        import leidenalg
    except ImportError:
        return {"status": "unavailable", "reason": "Leiden requires installed igraph and leidenalg runtime dependencies", "graph": graph, "communities": []}
    ids = [node["id"] for node in graph["nodes"]]
    index = {node_id: i for i, node_id in enumerate(ids)}
    edges = [(index[e["source"]], index[e["target"]]) for e in graph["edges"]]
    if not ids or not edges:
        return {"status": "complete", "algorithm": "Leiden", "graph": graph, "communities": []}
    network = ig.Graph(n=len(ids), edges=edges, directed=False)
    partition = leidenalg.find_partition(network, leidenalg.RBConfigurationVertexPartition, seed=0)
    communities = []
    for community_id, members in enumerate(partition):
        member_ids = [ids[i] for i in members]
        actor_ids = [value.removeprefix("actor:") for value in member_ids if value.startswith("actor:")]
        technique_ids = [value.removeprefix("technique:") for value in member_ids if value.startswith("technique:")]
        if actor_ids:
            communities.append({"community_id": community_id, "actor_ids": sorted(actor_ids), "technique_ids": sorted(technique_ids)})
    return {"status": "complete", "algorithm": "Leiden", "graph": graph, "communities": communities}
