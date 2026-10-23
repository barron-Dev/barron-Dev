from __future__ import annotations

from cyclothone.darkweb.tor_control import TorControlProofCollector, _bootstrap_complete


def test_bootstrap_status_parser_requires_exact_progress_100():
    assert _bootstrap_complete("NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=Done")
    assert not _bootstrap_complete("NOTICE BOOTSTRAP PROGRESS=90 TAG=ap_conn SUMMARY=Connected")
    assert not _bootstrap_complete("NOTICE BOOTSTRAP PROGRESS=1000 TAG=done SUMMARY=Done")
    assert not _bootstrap_complete("")


def test_control_proof_wait_is_bounded_and_does_not_invent_missing_events(monkeypatch):
    collector = TorControlProofCollector("request-1", host="127.0.0.1", port=9051, password="test")
    proof = {
        "route_verified": False,
        "hs_desc_content_received": False,
        "descriptor_fetched": False,
        "rendezvous_hop_verified": False,
        "stream_circuit_bound": False,
        "service_request_id": "request-1",
        "content_sha256": "a" * 64,
    }
    monkeypatch.setattr(collector, "proof_for", lambda seed, digest: dict(proof))
    result = collector.wait_for_proof(
        "http://" + "a" * 56 + ".onion/",
        "a" * 64,
        timeout_seconds=0,
    )
    assert result == proof
    assert result["route_verified"] is False


def test_control_proof_wait_returns_when_all_protocol_assertions_are_true(monkeypatch):
    collector = TorControlProofCollector("request-2", host="127.0.0.1", port=9051, password="test")
    proof = {
        "route_verified": True,
        "hs_desc_content_received": True,
        "descriptor_fetched": True,
        "rendezvous_hop_verified": True,
        "stream_circuit_bound": True,
        "service_request_id": "request-2",
        "content_sha256": "b" * 64,
    }
    monkeypatch.setattr(collector, "proof_for", lambda seed, digest: dict(proof))
    result = collector.wait_for_proof(
        "http://" + "b" * 56 + ".onion/",
        "b" * 64,
        timeout_seconds=0.2,
    )
    assert result["route_verified"] is True
    assert result["content_sha256"] == "b" * 64
