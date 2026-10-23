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


def test_request_scoped_socks_proxy_credentials_are_added_without_logging_them():
    collector = TorControlProofCollector("request-unique", host="127.0.0.1", port=9051, password="test")
    proxy = collector.proxy_for_request("socks5h://127.0.0.1:9050")
    assert proxy.startswith("socks5h://ct_")
    assert "@127.0.0.1:9050" in proxy
    assert collector._socks_username in proxy
    assert collector._socks_password in proxy
    other = TorControlProofCollector("request-other", host="127.0.0.1", port=9051, password="test")
    assert collector._socks_username != other._socks_username


def test_request_scoped_socks_proxy_rejects_non_socks_and_static_credentials():
    import pytest

    collector = TorControlProofCollector("request-1", host="127.0.0.1", port=9051, password="test")
    with pytest.raises(RuntimeError, match="tor_control_socks_proxy_invalid"):
        collector.proxy_for_request("http://127.0.0.1:9050")
    with pytest.raises(RuntimeError, match="tor_control_socks_proxy_must_not_contain_static_credentials"):
        collector.proxy_for_request("socks5://user:pass@127.0.0.1:9050")


def test_stream_event_captures_socks_auth_identity_for_isolation():
    from types import SimpleNamespace

    collector = TorControlProofCollector("request-1", host="127.0.0.1", port=9051, password="test")
    collector._on_stream(SimpleNamespace(
        address="a" * 56 + ".onion",
        status="SUCCEEDED",
        circ_id="17",
        socks_username=collector._socks_username,
    ))
    assert collector._streams[-1][1] == "a" * 56 + ".onion"
    assert collector._streams[-1][3] == "17"
    assert collector._streams[-1][4] == collector._socks_username


def test_hidden_service_event_accepts_hs_address_field():
    from types import SimpleNamespace

    collector = TorControlProofCollector("request-1", host="127.0.0.1", port=9051, password="test")
    collector._on_hs_desc_content(SimpleNamespace(
        hs_address="a" * 56,
        descriptor="bounded descriptor text",
    ))
    assert collector._descriptor_events["a" * 56 + ".onion"][-1][1:] == ("CONTENT", True)


def test_control_proof_requires_matching_request_socks_auth_and_built_rendezvous_circuit():
    import time

    collector = TorControlProofCollector("request-1", host="127.0.0.1", port=9051, password="test")
    host = "a" * 56 + ".onion"
    collector.controller = object()
    collector.bootstrapped = True
    collector.socks_auth_isolation_configured = True
    collector._starts[host] = 0.0
    collector._hsfetch_accepted.add(host)
    now = time.monotonic()
    collector._descriptor_events[host] = [
        (now, "RECEIVED", True),
        (now, "CONTENT", True),
    ]
    collector._circuits = [(now, "17", "BUILT", "HS_CLIENT_REND")]
    collector._streams = [(now, host, "SUCCEEDED", "17", collector._socks_username)]

    proof = collector.proof_for("http://" + host + "/", "c" * 64)
    assert proof["route_verified"] is True
    assert proof["stream_circuit_bound"] is True
    assert proof["socks_auth_bound"] is True
    assert proof["content_sha256"] == "c" * 64

    collector._streams = [(now, host, "SUCCEEDED", "17", "another-request")]
    proof = collector.proof_for("http://" + host + "/", "c" * 64)
    assert proof["route_verified"] is False
    assert proof["stream_circuit_bound"] is False
    assert proof["socks_auth_bound"] is False


def test_control_proxy_rejects_public_socks_endpoint():
    import pytest

    collector = TorControlProofCollector("request-1", host="127.0.0.1", port=9051, password="test")
    with pytest.raises(RuntimeError, match="tor_control_socks_proxy_must_be_private"):
        collector.proxy_for_request("socks5h://proxy.example.com:9050")


def test_control_port_range_is_validated():
    import pytest

    with pytest.raises(ValueError, match="tor_control_port_invalid"):
        TorControlProofCollector("request-1", host="127.0.0.1", port=70000, password="test")
