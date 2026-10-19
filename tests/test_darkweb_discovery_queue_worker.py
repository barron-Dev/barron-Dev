from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from cyclothone.darkweb.discovery_queue_worker import (
    DWDiscoveryQueueWorker,
    _AhmiaLinks,
    _candidate_onion_url,
    _search_term,
)


def test_candidate_onion_requires_v3_host_and_web_port():
    host = "a" * 56 + ".onion"
    assert _candidate_onion_url(f"http://{host}/listing") == f"http://{host}/listing"
    assert _candidate_onion_url(f"https://{host}:8443/") is None
    assert _candidate_onion_url("http://short.onion/") is None
    assert _candidate_onion_url(f"http://user:pass@{host}/") is None
    assert _candidate_onion_url("file:///etc/passwd") is None
    assert _candidate_onion_url(f"http://{host}/?q=private") is None


def test_ahmia_parser_only_collects_links_containing_onion_marker():
    parser = _AhmiaLinks()
    parser.feed(
        '<a href="http://'
        + "a" * 56
        + '.onion/">candidate</a><a href="https://example.com/">surface</a>'
    )
    assert len(parser.links) == 1
    assert parser.links[0].endswith(".onion/")


def test_search_term_is_bounded_and_strips_control_characters():
    term = _search_term("country:BJ;ignore", "corrections_prisons")
    assert ";" not in term
    assert "corrections prisons" in term
    assert len(term) < 200


@pytest.mark.asyncio
async def test_guarded_uses_job_id_and_lease_token_fencing(monkeypatch):
    worker = DWDiscoveryQueueWorker()
    worker._process = AsyncMock(return_value=("completed", {"candidate_count": 0}, None, 0))
    rpc = AsyncMock(return_value=True)
    monkeypatch.setattr("cyclothone.darkweb.discovery_queue_worker.supabase.rpc", rpc)

    await worker._guarded({"job_id": 42, "lease_token": "lease-uuid"})

    rpc.assert_awaited_once_with(
        "complete_dw_source_discovery_job",
        {
            "p_job_id": 42,
            "p_lease_token": "lease-uuid",
            "p_outcome": "completed",
            "p_error_code": None,
            "p_result_metadata": {"candidate_count": 0},
            "p_retry_after_seconds": 300,
            "p_max_attempts": 6,
        },
    )


@pytest.mark.asyncio
async def test_guarded_refuses_claim_without_lease_token(monkeypatch):
    worker = DWDiscoveryQueueWorker()
    rpc = AsyncMock()
    monkeypatch.setattr("cyclothone.darkweb.discovery_queue_worker.supabase.rpc", rpc)

    await worker._guarded({"job_id": 42})

    rpc.assert_not_awaited()


@pytest.mark.asyncio
async def test_unknown_discovery_job_is_dead_lettered_not_reported_success():
    worker = DWDiscoveryQueueWorker()
    outcome, metadata, error, retry_after = await worker._process(
        {
            "job_id": 7,
            "scope_key": "BJ",
            "category_slug": "unknown_category",
            "discovery_kind": "unknown_kind",
        }
    )
    assert outcome == "dead_letter"
    assert metadata["reason"] == "unsupported_discovery_job"
    assert error == "unsupported_discovery_job"
    assert retry_after == 0


@pytest.mark.asyncio
async def test_official_source_discovery_is_not_falsely_completed():
    worker = DWDiscoveryQueueWorker()
    outcome, metadata, error, retry_after = await worker._process(
        {
            "job_id": 7,
            "scope_key": "BJ",
            "category_slug": "corrections_prisons",
            "discovery_kind": "official_corrections_prison_source_discovery",
        }
    )
    assert outcome == "retry"
    assert metadata["reason"] == "official_source_adapter_not_integrated"
    assert error == "provider_adapter_not_integrated"
    assert retry_after == 3600


class _FakeResponse:
    status_code = 200
    headers = {"content-type": "text/html; charset=utf-8"}
    encoding = "utf-8"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def aiter_bytes(self):
        yield b"<html><title>Public official notice</title><body>Public information</body></html>"


class _FakeClient:
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    def stream(self, method, url):
        assert method == "GET"
        assert url.startswith("https://")
        return _FakeResponse()


@pytest.mark.asyncio
async def test_official_source_check_is_bounded_and_does_not_claim_country_coverage(monkeypatch):
    worker = DWDiscoveryQueueWorker()
    scope_rows = [
        {"display_name": "Benin", "scope_type": "country", "parent_scope_key": "west-africa"},
        {"display_name": "West Africa", "parent_scope_key": "africa"},
        {"display_name": "Africa", "parent_scope_key": None},
    ]
    monkeypatch.setattr(
        "cyclothone.darkweb.discovery_queue_worker.supabase.select_one",
        AsyncMock(side_effect=scope_rows),
    )
    catalog_update = AsyncMock(return_value={"id": "interpol_public_notices"})
    monkeypatch.setattr(
        "cyclothone.darkweb.discovery_queue_worker.supabase.update", catalog_update
    )
    monkeypatch.setattr(
        "cyclothone.darkweb.discovery_queue_worker.httpx.AsyncClient", _FakeClient
    )

    outcome, metadata, error, retry_after = await worker._check_official_endpoint(
        "country:bj",
        "criminal_justice_public_records",
        {"job_id": 3},
    )

    assert outcome == "completed"
    assert metadata["source_health_only"] is True
    assert metadata["country_coverage_claimed"] is False
    assert metadata["body_bytes_inspected"] > 0
    assert metadata["body_sha256"]
    assert metadata["integration_status_unchanged"] is True
    assert error is None
    assert retry_after == 300
    catalog_update.assert_awaited_once()
