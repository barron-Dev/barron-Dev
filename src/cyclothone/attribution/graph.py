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
        capec_ids = actor.get("capec_ids") or profile.get("capec_ids") or []
        for raw in capec_ids if isinstance(capec_ids, list) else []:
            capec = str(raw).strip().upper()
            if not capec.startswith("CAPEC-") or len(capec) > 12:
                continue
            capec_node = f"capec:{capec}"
            nodes[capec_node] = {"kind": "attack-pattern", "label": capec}
            edges.add((actor_node, capec_node))
    return {"nodes": [{"id": k, **nodes[k]} for k in sorted(nodes)], "edges": [{"source": a, "target": b} for a, b in sorted(edges)], "algorithm": "bipartite-actor-attack-technique-capec-v1"}


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
        capec_ids = [value.removeprefix("capec:") for value in member_ids if value.startswith("capec:")]
        if actor_ids:
            communities.append({"community_id": community_id, "actor_ids": sorted(actor_ids), "technique_ids": sorted(technique_ids), "capec_ids": sorted(capec_ids)})
    return {"status": "complete", "algorithm": "Leiden", "graph": graph, "communities": communities}


def build_actor_ecosystem_graph(actors: list[dict[str, Any]], relationships: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Build an evidence-derived actor, capability, infrastructure and victimology graph."""
    nodes: dict[str, dict[str, str]] = {}
    edges: set[tuple[str, str, str]] = set()
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
            node = f"technique:{technique}"
            nodes[node] = {"kind": "technique", "label": technique}
            edges.add((actor_node, node, "USES_TECHNIQUE"))
        capec_ids = profile.get("capec_ids") or actor.get("capec_ids") or []
        for raw in capec_ids if isinstance(capec_ids, list) else []:
            capec = str(raw).strip().upper()
            if not capec.startswith("CAPEC-") or len(capec) > 12:
                continue
            node = f"capec:{capec}"
            nodes[node] = {"kind": "attack-pattern", "label": capec}
            edges.add((actor_node, node, "ASSOCIATED_WITH_ATTACK_PATTERN"))
        infra = profile.get("infrastructure") or {}
        for kind in ("domains", "ips", "hosting_providers", "tls_certificates", "c2_frameworks"):
            for raw in infra.get(kind, []) if isinstance(infra, dict) else []:
                value = str(raw).strip().lower()[:256]
                if not value:
                    continue
                node = f"infrastructure:{kind}:{value}"
                nodes[node] = {"kind": "infrastructure", "label": value}
                edges.add((actor_node, node, "USES_INFRASTRUCTURE"))
        diamond = profile.get("diamond_model") or {}
        victim = diamond.get("victim") or {}
        for kind in ("sectors", "regions", "organisation_sizes"):
            for raw in victim.get(kind, []) if isinstance(victim, dict) else []:
                value = str(raw).strip().lower()[:128]
                if not value:
                    continue
                node = f"victim:{kind}:{value}"
                nodes[node] = {"kind": "victimology", "label": value}
                edges.add((actor_node, node, "TARGETS"))
    for relation in relationships or []:
        source = str(relation.get("source_actor_id") or "")
        target = str(relation.get("target_actor_id") or "")
        relation_type = str(relation.get("relationship_type") or "POSSIBLE_ASSOCIATION")
        if source and target and source != target:
            source_node, target_node = f"actor:{source}", f"actor:{target}"
            if source_node in nodes and target_node in nodes:
                edges.add((source_node, target_node, relation_type))
    return {
        "status": "complete", "algorithm": "evidence-derived-actor-ecosystem-v1",
        "nodes": [{"id": key, **nodes[key]} for key in sorted(nodes)],
        "edges": [{"source": source, "target": target, "relationship": kind} for source, target, kind in sorted(edges)],
    }
