from cyclothone.attribution.alerts import sign_payload
from cyclothone.attribution.cluster import assemble_activity_cluster
from cyclothone.attribution.graph import build_actor_technique_bipartite_graph


def test_cluster_has_all_diamond_vertices_and_deduplicates_infrastructure():
    records = [
        {"record_id": "1", "source_name": "feed-a", "infrastructure": {"domains": ["EXAMPLE.COM", "example.com"]}, "attack_techniques": ["T1059.001"], "evidence_hash": "a" * 64},
        {"record_id": "2", "source_name": "feed-b", "infrastructure": {"domains": ["example.com"]}, "attack_techniques": ["T1059.001"], "evidence_hash": "b" * 64},
    ]
    result = assemble_activity_cluster(records, tenant_id="tenant-1", cluster_key="watch-1")
    assert set(result["diamond_model"]) == {"adversary", "capability", "infrastructure", "victim"}
    assert result["infrastructure"]["domains"] == ["example.com"]
    assert result["independent_sources"] == ["feed-a", "feed-b"]
    assert result["activity_cluster_id"] == assemble_activity_cluster(records, tenant_id="tenant-1", cluster_key="watch-1")["activity_cluster_id"]


def test_cluster_rejects_missing_provenance():
    try:
        assemble_activity_cluster([{"source_name": "feed"}], tenant_id="tenant-1")
    except ValueError as exc:
        assert str(exc) == "cluster_requires_source_provenance"
    else:
        raise AssertionError("cluster without evidence IDs must fail closed")


def test_bipartite_graph_contains_actor_technique_edges():
    graph = build_actor_technique_bipartite_graph([
        {"actor_id": "actor-1", "primary_name": "Cluster 1", "attack_techniques": ["T1059.001", "T1566.001"]}
    ])
    assert len(graph["nodes"]) == 3
    assert len(graph["edges"]) == 2
    assert all(edge["source"].startswith("actor:") and edge["target"].startswith("technique:") for edge in graph["edges"])


def test_webhook_signature_is_stable_for_same_payload_and_timestamp():
    secret, body, timestamp = b"test-secret", b'{"event_id":"e-1"}', "1760000000"
    assert sign_payload(secret, body, timestamp) == sign_payload(secret, body, timestamp)
    assert sign_payload(secret, body, timestamp) != sign_payload(secret, body, "1760000001")
