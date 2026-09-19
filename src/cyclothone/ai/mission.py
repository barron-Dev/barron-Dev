from __future__ import annotations
import hashlib, json
from dataclasses import dataclass
from typing import Any

class MissionCompileError(ValueError): pass

@dataclass(frozen=True, slots=True)
class CompiledMission:
    mission_id: str
    version: int
    trigger_id: str
    nodes: tuple[dict[str, Any], ...]
    edges: tuple[tuple[str, str], ...]
    compiled_hash: str
    is_dag: bool = True

class MissionCompiler:
    def __init__(self, *, max_nodes: int = 256, max_edges: int = 1024) -> None:
        self.max_nodes, self.max_edges = max_nodes, max_edges

    def compile(self, definition: dict[str, Any]) -> CompiledMission:
        if not isinstance(definition, dict): raise MissionCompileError("definition must be an object")
        mission_id = str(definition.get("mission_id") or "")
        version = definition.get("version")
        if not mission_id or not isinstance(version, int) or version < 1: raise MissionCompileError("mission id/version required")
        raw_nodes, raw_edges = definition.get("nodes"), definition.get("edges")
        if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list): raise MissionCompileError("nodes and edges must be arrays")
        if not 1 <= len(raw_nodes) <= self.max_nodes or len(raw_edges) > self.max_edges: raise MissionCompileError("mission bounds exceeded")
        nodes: dict[str, dict[str, Any]] = {}; triggers = []
        for node in raw_nodes:
            if not isinstance(node, dict): raise MissionCompileError("node must be an object")
            nid, kind = str(node.get("id") or ""), str(node.get("kind") or "")
            if not nid or not kind or nid in nodes: raise MissionCompileError("invalid or duplicate node")
            if kind == "trigger": triggers.append(nid)
            if kind not in {"trigger","action","condition","parallel","finalize"}: raise MissionCompileError("unsupported node kind")
            nodes[nid] = {k: node[k] for k in sorted(node)}
        if len(triggers) != 1: raise MissionCompileError("mission requires exactly one trigger")
        edges: set[tuple[str,str]] = set()
        for edge in raw_edges:
            if not isinstance(edge, dict): raise MissionCompileError("edge must be an object")
            src, dst = str(edge.get("from") or ""), str(edge.get("to") or "")
            pair=(src,dst)
            if src not in nodes or dst not in nodes: raise MissionCompileError("dangling edge")
            if src == dst or pair in edges: raise MissionCompileError("self-edge or duplicate edge")
            edges.add(pair)
        incoming={n:0 for n in nodes}; outgoing={n:[] for n in nodes}
        for src,dst in edges: incoming[dst]+=1; outgoing[src].append(dst)
        queue=[n for n in nodes if incoming[n]==0]; visited=[]
        while queue:
            cur=queue.pop(0); visited.append(cur)
            for dst in sorted(outgoing[cur]):
                incoming[dst]-=1
                if incoming[dst]==0: queue.append(dst)
        if len(visited) != len(nodes): raise MissionCompileError("mission graph contains a cycle")
        reachable={triggers[0]}; stack=[triggers[0]]
        while stack:
            cur=stack.pop()
            for dst in outgoing[cur]:
                if dst not in reachable: reachable.add(dst); stack.append(dst)
        if reachable != set(nodes): raise MissionCompileError("mission contains unreachable nodes")
        if any(nodes[n]["kind"]=="finalize" and outgoing[n] for n in nodes): raise MissionCompileError("finalize node must terminate a path")
        canonical={"mission_id":mission_id,"version":version,"nodes":[nodes[n] for n in sorted(nodes)],"edges":[{"from":a,"to":b} for a,b in sorted(edges)]}
        digest=hashlib.sha256(json.dumps(canonical,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()).hexdigest()
        return CompiledMission(mission_id,version,triggers[0],tuple(canonical["nodes"]),tuple(sorted(edges)),digest,True)
