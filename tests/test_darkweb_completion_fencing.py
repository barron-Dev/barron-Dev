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


def test_native_onion_requires_every_tor_protocol_proof():
    from types import SimpleNamespace
    from cyclothone.darkweb.request_worker import _native_onion_route_proof_missing

    missing = _native_onion_route_proof_missing(SimpleNamespace())
    assert set(missing) == {
        "route_verified",
        "hs_desc_content_received",
        "descriptor_fetched",
        "rendezvous_hop_verified",
        "stream_circuit_bound",
    }

    proven = SimpleNamespace(
        route_verified=True,
        hs_desc_content_received=True,
        descriptor_fetched=True,
        rendezvous_hop_verified=True,
        stream_circuit_bound=True,
    )
    assert _native_onion_route_proof_missing(proven) == []


def test_truthy_non_boolean_tor_proof_is_not_accepted():
    from types import SimpleNamespace
    from cyclothone.darkweb.request_worker import _native_onion_route_proof_missing

    monitor = SimpleNamespace(
        route_verified=1,
        hs_desc_content_received="true",
        descriptor_fetched=True,
        rendezvous_hop_verified=True,
        stream_circuit_bound=True,
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
        route_verified=True,
        hs_desc_content_received=True,
        descriptor_fetched=True,
        rendezvous_hop_verified=True,
        stream_circuit_bound=True,
        seed_content_hash={},
        pages_checked=0,
    )
    reason, route_missing, content_missing = _native_onion_unavailability(monitor)
    assert reason == "onion_content_proof_unavailable"
    assert route_missing == []
    assert content_missing == ["content_sha256", "inspected_items"]


def test_inspected_item_ledger_count_uses_only_actual_content_counts():
    from cyclothone.darkweb.request_worker import _source_inspected_items

    assert _source_inspected_items({"items_inspected": 4}) == 4
    assert _source_inspected_items({"pages_checked": 3, "posts_checked": 8}) == 8
    assert _source_inspected_items({"seed_count": 20, "matches": 2}) == 0
