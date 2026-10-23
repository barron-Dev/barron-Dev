from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from cyclothone.darkweb.tor_control import TorControlProofCollector, _private_control_host


def _collector():
    collector = TorControlProofCollector("request-1", host="127.0.0.1", port=9051)
    collector.controller = object()
    collector.bootstrapped = True
    host = "a" * 56 + ".onion"
    collector._starts[host] = time.monotonic() - 2
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
    collector._streams = [(now, host, "SUCCEEDED", "17")]

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
    collector._streams = [(now, host, "SUCCEEDED", "17")]

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
