from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from cyclothone.darkweb.request_worker import DarkWebRequestWorker


@pytest.mark.asyncio
async def test_completion_passes_claim_attempt_as_fencing_token(monkeypatch):
    rpc = AsyncMock(return_value=True)
    monkeypatch.setattr("cyclothone.darkweb.request_worker.supabase.rpc", rpc)
    worker = DarkWebRequestWorker()

    await worker._complete(
        {"id": "00000000-0000-0000-0000-000000000001", "attempts": 2},
        "succeeded",
        "resolved",
        {"coverage": "partial"},
        None,
    )

    rpc.assert_awaited_once_with(
        "complete_service_request",
        {
            "p_id": "00000000-0000-0000-0000-000000000001",
            "p_attempt": 2,
            "p_state": "succeeded",
            "p_status": "resolved",
            "p_result": {"coverage": "partial"},
            "p_failure_code": None,
        },
    )



@pytest.mark.asyncio
async def test_completion_rejected_by_fence_is_not_treated_as_success(monkeypatch):
    rpc = AsyncMock(return_value=False)
    monkeypatch.setattr("cyclothone.darkweb.request_worker.supabase.rpc", rpc)
    worker = DarkWebRequestWorker()

    with pytest.raises(RuntimeError, match="completion_fence_rejected"):
        await worker._complete(
            {"id": "00000000-0000-0000-0000-000000000001", "attempts": 2},
            "succeeded",
            "resolved",
            {"coverage": "partial"},
            None,
        )

    rpc.assert_awaited_once()


def test_finding_persistence_requires_database_confirmation_of_finding_and_alert():
    from cyclothone.darkweb.request_worker import _require_recorded_finding

    recorded = _require_recorded_finding([{"finding_id": 123, "alert_id": "alert-1", "detection_id": "detection-1"}])
    assert recorded["finding_id"] == 123


@pytest.mark.parametrize("response", [None, [], [{}], [{"finding_id": 123}], [{"alert_id": "alert-1"}]])
def test_finding_persistence_rejects_unconfirmed_rpc_results(response):
    from cyclothone.darkweb.request_worker import _require_recorded_finding

    with pytest.raises(RuntimeError, match="finding_persistence_unconfirmed"):
        _require_recorded_finding(response)



@pytest.mark.asyncio
async def test_native_onion_content_match_persists_trust_evidence_before_finding_write(monkeypatch):
    from cyclothone.darkweb.pullers import Finding

    persisted = {
        "content_uri": "supabase://dw-evidence-private/tenant/subject/request/evidence.txt",
        "content_sha256": "a" * 64,
        "readback_sha256_verified": True,
        "finding_class": "candidate_evidence_not_verified",
    }
    persist = AsyncMock(return_value=persisted)
    monkeypatch.setattr("cyclothone.darkweb.request_worker.record_target_matched_onion_evidence", persist)
    worker = DarkWebRequestWorker()
    finding = Finding(
        "native_onion", "domain", "owned-example.com", "exact public onion match",
        "critical", "http://" + "a" * 56 + ".onion/leak",
        {"target_match_in_content": True, "observed_at": "2026-10-22T00:00:00+00:00"},
        evidence_excerpt="Page says owned-example.com was exposed.",
    )
    metadata = dict(finding.metadata)

    result = await worker._persist_native_onion_evidence(
        finding,
        tenant_id="tenant-1",
        watchlist_id="watchlist-1",
        service_request_id="request-1",

        expected_attempt=1,
        metadata=metadata,
    )

    assert result == persisted
    persist.assert_awaited_once()
    assert metadata["durable_evidence"]["content_sha256"] == "a" * 64
    assert metadata["durable_evidence"]["classification"] == "candidate_evidence_not_verified"


@pytest.mark.asyncio
async def test_native_onion_url_only_match_does_not_create_content_evidence(monkeypatch):
    from cyclothone.darkweb.pullers import Finding

    persist = AsyncMock()
    monkeypatch.setattr("cyclothone.darkweb.request_worker.record_target_matched_onion_evidence", persist)
    worker = DarkWebRequestWorker()
    finding = Finding(
        "native_onion", "domain", "owned-example.com", "URL-only match",
        "critical", "http://" + "a" * 56 + ".onion/owned-example.com",
        {"target_match_in_content": False, "target_match_in_url": True},
    )
    metadata = dict(finding.metadata)

    result = await worker._persist_native_onion_evidence(
        finding,
        tenant_id="tenant-1",
        watchlist_id="watchlist-1",
        service_request_id="request-1",

        expected_attempt=1,
        metadata=metadata,
    )

    assert result is None
    persist.assert_not_awaited()
    assert "durable_evidence" not in metadata


@pytest.mark.asyncio
async def test_native_onion_content_match_without_safe_excerpt_fails_closed(monkeypatch):
    from cyclothone.darkweb.pullers import Finding

    persist = AsyncMock()
    monkeypatch.setattr("cyclothone.darkweb.request_worker.record_target_matched_onion_evidence", persist)
    worker = DarkWebRequestWorker()
    finding = Finding(
        "native_onion", "domain", "owned-example.com", "match without excerpt",
        "critical", "http://" + "a" * 56 + ".onion/leak",
        {"target_match_in_content": True},
    )

    with pytest.raises(RuntimeError, match="native_onion_matched_content_without_safe_evidence_excerpt"):
        await worker._persist_native_onion_evidence(
            finding,
            tenant_id="tenant-1",
            watchlist_id="watchlist-1",
            service_request_id="request-1",

            expected_attempt=1,
            metadata=dict(finding.metadata),
        )
    persist.assert_not_awaited()


def test_archived_ransomwatch_findings_never_enter_current_results():
    from cyclothone.darkweb.request_worker import _is_current_finding

    assert not _is_current_finding(
        {"source_id": "ransomwatch", "finding_class": "historical_archive"},
        "request-1",
    )


def test_legacy_native_onion_row_without_request_evidence_is_not_current():
    from cyclothone.darkweb.request_worker import _is_current_finding

    assert not _is_current_finding(
        {"source_id": "native_onion", "finding_class": "historical_archive", "source_metadata": {}},
        "request-1",
    )


def test_native_onion_current_candidate_requires_this_requests_durable_evidence():
    from cyclothone.darkweb.request_worker import _is_current_finding

    row = {
        "source_id": "native_onion",
        "finding_class": "historical_archive",
        "source_metadata": {
            "service_request_id": "request-1",
            "durable_evidence": {"content_uri": "supabase://private/object"},
        },
    }
    assert _is_current_finding(row, "request-1")
    assert not _is_current_finding(row, "request-2")


def test_surface_public_findings_remain_separate_from_historical_archive():
    from cyclothone.darkweb.request_worker import _is_current_finding

    assert _is_current_finding(
        {"source_id": "telegram_public", "finding_class": "surface_public"},
        "request-1",
    )


def test_new_surface_finding_is_current_only_when_bound_to_this_request():
    from cyclothone.darkweb.request_worker import _is_current_finding

    row = {
        "source_id": "telegram_public",
        "finding_class": "historical_archive",
        "source_metadata": {"service_request_id": "request-1"},
    }
    assert _is_current_finding(row, "request-1")
    assert not _is_current_finding(row, "request-2")
    assert not _is_current_finding(
        {"source_id": "telegram_public", "finding_class": "historical_archive", "source_metadata": {}},
        "request-1",
    )


def test_native_onion_requires_per_seed_tor_protocol_proof():
    from types import SimpleNamespace
    from cyclothone.darkweb.request_worker import _native_onion_route_proof_missing

    monitor = SimpleNamespace(
        service_request_id="request-1",
        seed_content_hash={"seed-a": "a" * 64},
        seed_route_proofs={},
    )
    assert set(_native_onion_route_proof_missing(monitor)) == {
        "route_verified",
        "hs_desc_content_received",
        "descriptor_fetched",
        "rendezvous_hop_verified",
        "stream_circuit_bound",
    }

    monitor.seed_route_proofs = {
        "seed-a": {
            "service_request_id": "request-1",
            "content_sha256": "a" * 64,
            "tor_control_authenticated": True,
            "tor_bootstrap_complete": True,
            "tor_socks_auth_isolation_configured": True,
            "hsfetch_accepted": True,
            "route_verified": True,
            "hs_desc_content_received": True,
            "descriptor_fetched": True,
            "rendezvous_hop_verified": True,
            "stream_circuit_bound": True,
        }
    }
    assert _native_onion_route_proof_missing(monitor) == []


def test_global_tor_flags_cannot_substitute_for_per_seed_proof():
    from types import SimpleNamespace
    from cyclothone.darkweb.request_worker import _native_onion_route_proof_missing

    monitor = SimpleNamespace(
        route_verified=True,
        hs_desc_content_received=True,
        descriptor_fetched=True,
        rendezvous_hop_verified=True,
        stream_circuit_bound=True,
        service_request_id="request-1",
        seed_content_hash={"seed-a": "a" * 64},
        seed_route_proofs={},
    )
    assert len(_native_onion_route_proof_missing(monitor)) == 5

def test_truthy_non_boolean_tor_proof_is_not_accepted():
    from types import SimpleNamespace
    from cyclothone.darkweb.request_worker import _native_onion_route_proof_missing

    monitor = SimpleNamespace(
        service_request_id="request-1",
        seed_content_hash={"seed-a": "a" * 64},
        seed_route_proofs={
            "seed-a": {
                "service_request_id": "request-1",
                "content_sha256": "a" * 64,
                "route_verified": 1,
                "hs_desc_content_received": "true",
                "descriptor_fetched": True,
                "rendezvous_hop_verified": True,
                "stream_circuit_bound": True,
            }
        },
    )
    assert _native_onion_route_proof_missing(monitor) == [
        "route_verified",
        "hs_desc_content_received",
    ]


def test_native_onion_content_proof_requires_real_digest_and_inspected_page():
    from types import SimpleNamespace
    from cyclothone.darkweb.request_worker import (
        _native_onion_content_proof_missing,
        _native_onion_content_sha256,
    )

    monitor = SimpleNamespace(seed_content_hash={}, pages_checked=0)
    assert _native_onion_content_proof_missing(monitor) == ["content_sha256", "inspected_items"]
    assert _native_onion_content_sha256(monitor) is None

    monitor.seed_content_hash = {"seed": "A" * 64}
    monitor.pages_checked = 1
    assert _native_onion_content_proof_missing(monitor) == []
    assert _native_onion_content_sha256(monitor) == "a" * 64


def test_native_onion_http_content_without_tor_protocol_proof_is_unavailable():
    from types import SimpleNamespace
    from cyclothone.darkweb.request_worker import _native_onion_unavailability

    monitor = SimpleNamespace(
        seed_content_hash={"seed": "a" * 64},
        pages_checked=1,
    )
    reason, route_missing, content_missing = _native_onion_unavailability(monitor)
    assert reason == "tor_route_proof_unavailable"
    assert len(route_missing) == 5
    assert content_missing == []


def test_native_onion_route_proof_without_inspected_content_is_unavailable():
    from types import SimpleNamespace
    from cyclothone.darkweb.request_worker import _native_onion_unavailability

    monitor = SimpleNamespace(
        service_request_id="request-1",
        seed_content_hash={"seed-a": "a" * 64},
        seed_route_proofs={
            "seed-a": {
                "service_request_id": "request-1",
                "content_sha256": "a" * 64,
                "tor_control_authenticated": True,
                "tor_bootstrap_complete": True,
            "tor_socks_auth_isolation_configured": True,
                "hsfetch_accepted": True,
                "route_verified": True,
                "hs_desc_content_received": True,
                "descriptor_fetched": True,
                "rendezvous_hop_verified": True,
                "stream_circuit_bound": True,
            }
        },
        pages_checked=0,
    )
    reason, route_missing, content_missing = _native_onion_unavailability(monitor)
    assert reason == "onion_content_proof_unavailable"
    assert route_missing == []
    assert content_missing == ["inspected_items"]


def test_inspected_item_ledger_count_uses_only_actual_content_counts():
    from cyclothone.darkweb.request_worker import _source_inspected_items

    assert _source_inspected_items({"items_inspected": 4}) == 4
    assert _source_inspected_items({"pages_checked": 3, "posts_checked": 8}) == 8
    assert _source_inspected_items({"seed_count": 20, "matches": 2}) == 0


def test_native_onion_seed_status_requires_request_and_digest_binding():
    from types import SimpleNamespace
    from cyclothone.darkweb.request_worker import _native_onion_seed_route_proven

    fields = {
        "service_request_id": "request-1",
        "content_sha256": "a" * 64,
        "route_verified": True,
        "hs_desc_content_received": True,
        "descriptor_fetched": True,
        "rendezvous_hop_verified": True,
        "stream_circuit_bound": True,
    }
    monitor = SimpleNamespace(
        service_request_id="request-1",
        seed_content_hash={"seed": "a" * 64},
        seed_route_proofs={"seed": dict(fields)},
    )
    assert _native_onion_seed_route_proven(monitor, "seed")
    monitor.seed_route_proofs["seed"]["service_request_id"] = "request-2"
    assert not _native_onion_seed_route_proven(monitor, "seed")
    monitor.seed_route_proofs["seed"]["service_request_id"] = "request-1"
    monitor.seed_route_proofs["seed"]["content_sha256"] = "b" * 64
    assert not _native_onion_seed_route_proven(monitor, "seed")


def test_ransomwatch_current_feed_only_alerts_for_exact_customer_target():
    from types import SimpleNamespace
    from cyclothone.darkweb.request_worker import _partition_ransomwatch_findings

    exact = SimpleNamespace(
        kind="company_name",
        matched_value="acme corp",
        source_url="https://example.invalid/post",
        metadata={"temporal_class": "current_feed", "victim_name": "acme corp"},
    )
    unrelated = SimpleNamespace(
        kind="company_name",
        matched_value="other corp",
        source_url="https://example.invalid/post-2",
        metadata={"temporal_class": "current_feed", "victim_name": "other corp"},
    )
    current, historical, future = _partition_ransomwatch_findings(
        [exact, unrelated], "company_name", "acme corp"
    )
    assert current == [exact]
    assert historical == []
    assert future == []


def test_ransomwatch_historical_and_future_entries_are_not_current_alerts():
    from types import SimpleNamespace
    from cyclothone.darkweb.request_worker import _partition_ransomwatch_findings

    def finding(temporal_class):
        return SimpleNamespace(
            kind="company_name",
            matched_value="acme corp",
            source_url="https://example.invalid/post",
            metadata={"temporal_class": temporal_class, "victim_name": "acme corp"},
        )

    current, historical, future = _partition_ransomwatch_findings(
        [finding("historical_archive"), finding("future_dated")],
        "company_name", "acme corp"
    )
    assert current == []
    assert len(historical) == 1
    assert len(future) == 1


def test_tor_control_proof_requires_hsfetch_descriptor_content_and_bound_rendezvous():
    from cyclothone.darkweb.tor_control import TorControlProofCollector

    host = "a" * 56 + ".onion"
    collector = TorControlProofCollector("request-1", host="127.0.0.1", port=9051)
    collector.controller = object()
    collector.bootstrapped = True
    collector.tor_version = "test-version"
    collector._starts[host] = 1.0
    collector._hsfetch_accepted.add(host)
    collector._descriptor_events[host] = [
        (2.0, "RECEIVED", True),
        (2.1, "CONTENT", True),
    ]
    collector._circuits = [(2.5, "77", "BUILT", "HS_CLIENT_REND")]
    collector._streams = [(3.0, host, "SUCCEEDED", "77", collector._socks_username)]

    proof = collector.proof_for("http://" + host + "/", "b" * 64)
    assert proof["route_verified"] is True
    assert proof["hs_desc_content_received"] is True
    assert proof["descriptor_fetched"] is True
    assert proof["rendezvous_hop_verified"] is True
    assert proof["stream_circuit_bound"] is True
    assert proof["hsfetch_accepted"] is True
    assert proof["service_request_id"] == "request-1"
    assert proof["content_sha256"] == "b" * 64


def test_tor_control_proof_fails_closed_without_accepted_hsfetch():
    from cyclothone.darkweb.tor_control import TorControlProofCollector

    host = "a" * 56 + ".onion"
    collector = TorControlProofCollector("request-1", host="127.0.0.1", port=9051)
    collector.controller = object()
    collector.bootstrapped = True
    collector._starts[host] = 1.0
    collector._descriptor_events[host] = [
        (2.0, "RECEIVED", True),
        (2.1, "CONTENT", True),
    ]
    collector._circuits = [(2.5, "77", "BUILT", "HS_CLIENT_REND")]
    collector._streams = [(3.0, host, "SUCCEEDED", "77")]

    proof = collector.proof_for("http://" + host + "/", "b" * 64)
    assert proof["hsfetch_accepted"] is False
    assert proof["route_verified"] is False
    assert proof["descriptor_fetched"] is False
    assert proof["hs_desc_content_received"] is False


def test_native_onion_protocol_evidence_is_bounded_and_excludes_descriptor_content():
    from types import SimpleNamespace
    from cyclothone.darkweb.request_worker import _native_onion_protocol_evidence

    monitor = SimpleNamespace(
        tor_control_status="authenticated",
        tor_control_authenticated=True,
        tor_bootstrap_complete=True,
        tor_version="0.4.x",
        seed_route_proofs={
            "http://" + "a" * 56 + ".onion/": {
                "service_request_id": "request-1",
                "content_sha256": "a" * 64,
                "descriptor_event_count": 2,
                "route_verified": True,
                "hs_desc_content_received": True,
                "descriptor_fetched": True,
                "rendezvous_hop_verified": True,
                "stream_circuit_bound": True,
            }
        },
    )
    evidence = _native_onion_protocol_evidence(monitor)
    assert evidence["control_authenticated"] is True
    assert evidence["bootstrap_complete"] is True
    assert evidence["seed_proofs"][0]["proof"]["route_verified"] is True
    assert "descriptor" not in str(evidence).lower() or "descriptor_event_count" in str(evidence)


def test_temporal_observation_rpc_response_must_bind_tenant_request_and_entry():
    from cyclothone.darkweb.request_worker import _require_temporal_observation_confirmation

    row = {
        "observation_id": "observation-1",
        "tenant_id": "tenant-1",
        "watchlist_id": "watchlist-1",
        "service_request_id": "request-1",
        "entry_hash": "a" * 64,
        "temporal_class": "historical_archive",
    }
    assert _require_temporal_observation_confirmation(
        [row],
        request_id="request-1",
        tenant_id="tenant-1",
        watchlist_id="watchlist-1",
        entry_hash="a" * 64,
        temporal_class="historical_archive",
    ) == row

    with pytest.raises(RuntimeError, match="ransomwatch_temporal_observation_unconfirmed"):
        _require_temporal_observation_confirmation(
            [{**row, "tenant_id": "tenant-2"}],
            request_id="request-1",
            tenant_id="tenant-1",
            watchlist_id="watchlist-1",
            entry_hash="a" * 64,
            temporal_class="historical_archive",
        )
