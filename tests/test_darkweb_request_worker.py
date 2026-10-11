from unittest.mock import AsyncMock, patch

import pytest

from cyclothone.darkweb.request_worker import (
    DarkWebRequestWorker,
    _coverage_state,
    normalize_target,
)


def test_domain_target_is_normalized_without_path() -> None:
    assert normalize_target(" HTTPS://Example.COM/path ", "domain") == "example.com"


def test_private_or_internal_domain_target_is_rejected() -> None:
    with pytest.raises(ValueError, match="private_or_internal_target"):
        normalize_target("localhost", "domain")


def test_coverage_does_not_claim_success_when_no_source_was_checked() -> None:
    assert _coverage_state([
        {"source": "hibp", "state": "unavailable"},
        {"source": "github_code", "state": "failed"},
    ]) == "none"


def test_coverage_distinguishes_partial_provider_checks() -> None:
    assert _coverage_state([
        {"source": "ransomwatch", "state": "checked"},
        {"source": "hibp", "state": "unavailable"},
    ]) == "partial"


def test_coverage_reports_only_all_configured_checks() -> None:
    assert _coverage_state([
        {"source": "ransomwatch", "state": "checked"},
        {"source": "hibp", "state": "checked"},
    ]) == "all_configured_sources_checked"


@pytest.mark.asyncio
async def test_completion_rpc_is_fenced_by_current_attempt() -> None:
    worker = DarkWebRequestWorker()
    request = {"id": "request-1", "attempts": 2}
    with patch(
        "cyclothone.darkweb.request_worker.supabase.rpc",
        new=AsyncMock(return_value=True),
    ) as rpc:
        await worker._complete(request, "succeeded", "resolved", {"findings": []}, None)

    rpc.assert_awaited_once_with("complete_service_request", {
        "p_id": "request-1",
        "p_attempt": 2,
        "p_state": "succeeded",
        "p_status": "resolved",
        "p_result": {"findings": []},
        "p_failure_code": None,
    })


@pytest.mark.asyncio
async def test_stale_attempt_completion_is_rejected_without_fallback_write() -> None:
    worker = DarkWebRequestWorker()
    request = {"id": "request-1", "attempts": 1}
    with patch(
        "cyclothone.darkweb.request_worker.supabase.rpc",
        new=AsyncMock(return_value=False),
    ) as rpc:
        with pytest.raises(RuntimeError, match="completion_fence_rejected"):
            await worker._complete(request, "succeeded", "resolved", {"findings": []}, None)

    rpc.assert_awaited_once()
