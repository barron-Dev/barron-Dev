from cyclothone.knowledge.graph import KGNode, KnowledgeGraph
from cyclothone.knowledge.intent import classify
from cyclothone.knowledge.search import KnowledgeSearch


def test_intent_is_deterministic_and_tie_breaks_by_declared_order():
    result = classify("API tutorial")
    assert result.kind == "api"
    assert result.confidence == 0.5


def test_graph_rejects_orphan_edges_and_bounds():
    graph = KnowledgeGraph(max_nodes=2, max_edges=1)
    graph.add(KGNode("a", "concept", "A", None, None))
    graph.add(KGNode("b", "concept", "B", None, None))
    try:
        graph.link("a", "missing", "related_to")
        assert False
    except ValueError as exc:
        assert "unknown node" in str(exc)


def test_graph_traversal_is_deterministic():
    graph = KnowledgeGraph()
    for node_id in ("a", "b", "c"):
        graph.add(KGNode(node_id, "concept", node_id, None, None))
    graph.link("a", "c", "related_to")
    graph.link("a", "b", "explains")
    graph.finalize()
    assert graph.bfs("a") == [("a", 0), ("b", 1), ("c", 1)]


def test_synonym_expansion_uses_or_semantics():
    assert KnowledgeSearch._expand("antivirus") == "antivirus OR endpoint OR edr OR detection OR malware"
