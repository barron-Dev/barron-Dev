from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from cyclothone.darkweb.tor_control import TorControlProofCollector, _private_control_host


def _collector():
    collector = TorControlProofCollector("request-1", host="127.0.0.1", port=9051)
    collector.controller = object()
    collector.bootstrapped = True
    collector.socks_auth_isolation_configured = True
    host = "a" * 56 + ".onion"
    collector._starts[host] = time.monotonic() - 2
    collector._hsfetch_accepted.add(host)
    return collector, "http://" + host + "/"


def test_tor_proof_requires_descriptor_content_and_matching_rendezvous_stream():
    collector, seed = _collector()
    host = "a" * 56 + ".onion"
    now = time.monotonic()
    collector._descriptor_events[host] = [
        (now, "RECEIVED", True),
        (now, "CONTENT", True),
    ]
    collector._circuits = [(now, "17", "BUILT", "HS_CLIENT_REND")]
    collector._streams = [(now, host, "SUCCEEDED", "17", collector._socks_username)]

    collector.complete_seed_response(seed, "A" * 64)
    proof = collector.proof_for(seed, "A" * 64)
    assert proof["route_verified"] is True
    assert proof["hs_desc_content_received"] is True
    assert proof["descriptor_fetched"] is True
    assert proof["rendezvous_hop_verified"] is True
    assert proof["stream_circuit_bound"] is True
    assert proof["service_request_id"] == "request-1"
    assert proof["content_sha256"] == "a" * 64


def test_tor_proof_rejects_stream_not_bound_to_built_rendezvous_circuit():
    collector, seed = _collector()
    host = "a" * 56 + ".onion"
    now = time.monotonic()
    collector._descriptor_events[host] = [(now, "RECEIVED", True), (now, "CONTENT", True)]
    collector._circuits = [(now, "17", "BUILT", "GENERAL")]
    collector._streams = [(now, host, "SUCCEEDED", "17", collector._socks_username)]

    collector.complete_seed_response(seed, "b" * 64)
    proof = collector.proof_for(seed, "b" * 64)
    assert proof["route_verified"] is False
    assert proof["rendezvous_hop_verified"] is False
    assert proof["stream_circuit_bound"] is False


def test_tor_proof_does_not_reuse_events_from_before_seed_attempt():
    collector, seed = _collector()
    host = "a" * 56 + ".onion"
    old = collector._starts[host] - 1
    collector._descriptor_events[host] = [(old, "RECEIVED", True), (old, "CONTENT", True)]
    collector._circuits = [(old, "17", "BUILT", "HS_CLIENT_REND")]
    collector._streams = [(old, host, "SUCCEEDED", "17")]

    collector.complete_seed_response(seed, "c" * 64)
    proof = collector.proof_for(seed, "c" * 64)
    assert proof["hs_desc_content_received"] is False
    assert proof["descriptor_fetched"] is False
    assert proof["route_verified"] is False


@pytest.mark.parametrize("host", ["example.com", "8.8.8.8", "tor.example.org"])
def test_tor_control_endpoint_rejects_public_hosts(host):
    assert _private_control_host(host) is False


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "tor", "tor.railway.internal"])
def test_tor_control_endpoint_accepts_loopback_or_private_service_names(host):
    assert _private_control_host(host) is True


def test_tor_descriptor_events_without_onion_suffix_normalize_to_seed_host():
    collector, _ = _collector()
    address = "a" * 56
    assert collector._host_from_event(SimpleNamespace(address=address)) == address + ".onion"


@pytest.mark.parametrize("status,expected", [
    ("NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=Done", True),
    ("NOTICE BOOTSTRAP PROGRESS=99 TAG=loading SUMMARY=Loading", False),
    ("PROGRESS=1000", False),
    ("", False),
])
def test_tor_bootstrap_requires_exact_completion_marker(status, expected):
    from cyclothone.darkweb.tor_control import _bootstrap_complete

    assert _bootstrap_complete(status) is expected


def test_tor_control_start_requires_request_id_before_connecting():
    collector = TorControlProofCollector("", host="127.0.0.1", port=9051)
    with pytest.raises(RuntimeError, match="tor_control_request_id_required"):
        collector.start()


def test_tor_control_environment_requires_explicit_auth_material(monkeypatch):
    monkeypatch.setenv("CYCLOTHONE_DW_TOR_CONTROL_ENABLED", "true")
    monkeypatch.setenv("CYCLOTHONE_DW_TOR_CONTROL_HOST", "127.0.0.1")
    monkeypatch.delenv("CYCLOTHONE_DW_TOR_CONTROL_PASSWORD", raising=False)
    monkeypatch.delenv("CYCLOTHONE_DW_TOR_CONTROL_COOKIE", raising=False)
    with pytest.raises(RuntimeError, match="tor_control_auth_material_required"):
        TorControlProofCollector.from_env("request-1")



def test_request_proxy_uses_unique_request_scoped_socks_credentials():
    from urllib.parse import urlsplit, unquote

    collector = TorControlProofCollector("request-1", host="127.0.0.1", port=9051)
    proxy = collector.proxy_for_request("socks5h://127.0.0.1:9050")
    parsed = urlsplit(proxy)
    assert parsed.scheme == "socks5h"
    assert parsed.hostname == "127.0.0.1"
    assert unquote(parsed.username) == collector._socks_username
    assert unquote(parsed.password) == collector._socks_password
    assert collector._socks_username not in {"", "default", "cyclothone"}


def test_tor_route_proof_fails_when_socks_auth_isolation_is_not_configured():
    collector, seed = _collector()
    collector.socks_auth_isolation_configured = False
    host = "a" * 56 + ".onion"
    now = time.monotonic()
    collector._descriptor_events[host] = [
        (now, "RECEIVED", True),
        (now, "CONTENT", True),
    ]
    collector._circuits = [(now, "17", "BUILT", "HS_CLIENT_REND")]
    collector._streams = [(now, host, "SUCCEEDED", "17", collector._socks_username)]

    collector.complete_seed_response(seed, "d" * 64)
    proof = collector.proof_for(seed, "d" * 64)
    assert proof["tor_socks_auth_isolation_configured"] is False
    assert proof["route_verified"] is False


def test_tor_route_proof_is_bound_to_each_request_and_response_digest():
    collector, seed = _collector()
    host = "a" * 56 + ".onion"
    now = time.monotonic()
    collector._descriptor_events[host] = [
        (now, "RECEIVED", True),
        (now, "CONTENT", True),
    ]
    collector._circuits = [(now, "17", "BUILT", "HS_CLIENT_REND")]
    collector._streams = [(now, host, "SUCCEEDED", "17", collector._socks_username)]

    collector.complete_seed_response(seed, "E" * 64)
    proof = collector.proof_for(seed, "E" * 64)
    assert proof["service_request_id"] == "request-1"
    assert proof["content_sha256"] == "e" * 64
    assert proof["tor_control_authenticated"] is True
    assert proof["tor_bootstrap_complete"] is True
    assert proof["hsfetch_accepted"] is True


def test_tor_proof_rejects_digest_not_bound_to_completed_response():
    collector, seed = _collector()
    host = "a" * 56 + ".onion"
    now = time.monotonic()
    collector._descriptor_events[host] = [(now, "RECEIVED", True), (now, "CONTENT", True)]
    collector._circuits = [(now, "17", "BUILT", "HS_CLIENT_REND")]
    collector._streams = [(now, host, "SUCCEEDED", "17", collector._socks_username)]
    collector.complete_seed_response(seed, "f" * 64)

    proof = collector.proof_for(seed, "e" * 64)
    assert proof["response_window_bound"] is False
    assert proof["content_sha256"] is None
    assert proof["route_verified"] is False


def test_tor_proof_rejects_events_after_response_window():
    collector, seed = _collector()
    host = "a" * 56 + ".onion"
    collector.complete_seed_response(seed, "a" * 64)
    after = time.monotonic() + 1
    collector._descriptor_events[host] = [(after, "RECEIVED", True), (after, "CONTENT", True)]
    collector._circuits = [(after, "17", "BUILT", "HS_CLIENT_REND")]
    collector._streams = [(after, host, "SUCCEEDED", "17", collector._socks_username)]

    proof = collector.proof_for(seed, "a" * 64)
    assert proof["response_window_bound"] is True
    assert proof["route_verified"] is False
    assert proof["descriptor_fetched"] is False


def test_hs_desc_content_event_accepts_stem_descriptor_object_without_retaining_it():
    collector, seed = _collector()
    host = "a" * 56 + ".onion"
    event = SimpleNamespace(address="a" * 56, descriptor=object())
    collector._on_hs_desc_content(event)
    recorded = collector._descriptor_events[host][-1]
    assert recorded[1] == "CONTENT"
    assert recorded[2] is True
    assert len(recorded) == 3


def test_hs_desc_content_event_rejects_empty_descriptor():
    collector, _ = _collector()
    host = "a" * 56 + ".onion"
    collector._on_hs_desc_content(SimpleNamespace(address="a" * 56, descriptor=None))
    assert collector._descriptor_events[host][-1][2] is False
