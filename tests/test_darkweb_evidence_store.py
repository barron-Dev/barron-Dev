import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from cyclothone.darkweb.evidence_store import (
    MAX_EVIDENCE_BYTES,
    evidence_object_path,
    store_and_verify_evidence,
)


class _Bucket:
    def __init__(self, tamper=False, timeout_after_write=False):
        self.stored = None
        self.tamper = tamper
        self.timeout_after_write = timeout_after_write
        self.upload_calls = 0
        self.upload_options = None
        self.path = None

    async def upload(self, path, content, file_options=None):
        self.upload_calls += 1
        self.path = path
        if self.stored is not None:
            raise RuntimeError("object already exists")
        self.stored = bytes(content)
        self.upload_options = file_options
        if self.timeout_after_write:
            self.timeout_after_write = False
            raise TimeoutError("simulated timeout after storage commit")

    async def download(self, path):
        assert path == self.path
        if self.tamper:
            return self.stored + b"tampered"
        return self.stored


class _Storage:
    def __init__(self, tamper=False):
        self.bucket = _Bucket(tamper=tamper)
        self.bucket_name = None

    def from_(self, bucket):
        self.bucket_name = bucket
        return self.bucket


@pytest.mark.asyncio
async def test_upload_reads_back_and_verifies_exact_sanitized_bytes():
    storage = _Storage()
    text = "Target example.test observed on page."
    result = await store_and_verify_evidence(
        storage,
        object_path="tenant/subject/request/evidence.txt",
        sanitized_text=text,
    )
    assert storage.bucket_name == "dw-evidence-private"
    assert result.sha256 == hashlib.sha256(text.encode()).hexdigest()
    assert result.size_bytes == len(text.encode())
    assert storage.bucket.upload_options["upsert"] == "false"


@pytest.mark.asyncio
async def test_upload_timeout_after_commit_is_reconciled_by_exact_readback():
    storage = _Storage()
    storage.bucket.timeout_after_write = True
    result = await store_and_verify_evidence(
        storage,
        object_path="tenant/subject/request/evidence.txt",
        sanitized_text="Target example.test",
    )
    assert result.sha256 == hashlib.sha256(b"Target example.test").hexdigest()
    assert storage.bucket.upload_calls == 1


@pytest.mark.asyncio
async def test_readback_tampering_fails_closed():
    storage = _Storage(tamper=True)
    with pytest.raises(RuntimeError, match="dw_evidence_readback_integrity_mismatch"):
        await store_and_verify_evidence(
            storage,
            object_path="tenant/subject/request/evidence.txt",
            sanitized_text="Target example.test",
        )


@pytest.mark.asyncio
async def test_empty_or_oversized_evidence_is_rejected_before_upload():
    storage = _Storage()
    with pytest.raises(ValueError, match="dw_evidence_empty_content"):
        await store_and_verify_evidence(storage, object_path="t/s/r/e.txt", sanitized_text="  ")
    with pytest.raises(ValueError, match="dw_evidence_content_too_large"):
        await store_and_verify_evidence(
            storage,
            object_path="t/s/r/e.txt",
            sanitized_text="x" * (MAX_EVIDENCE_BYTES + 1),
        )


def test_evidence_paths_require_opaque_safe_segments():
    assert evidence_object_path(
        tenant_id="tenant_1", subject_id="subject-2", request_id="request3", evidence_id="evidence4"
    ) == "tenant_1/subject-2/request3/evidence4.txt"
    with pytest.raises(ValueError, match="dw_evidence_invalid_path_segment"):
        evidence_object_path(tenant_id="../escape", subject_id="s", request_id="r", evidence_id="e")


from types import SimpleNamespace

from cyclothone.darkweb.evidence_store import record_target_matched_onion_evidence


class _ServiceClient:
    def __init__(self, storage, evidence_tenant="tenant-1"):
        self.storage = storage
        self.evidence_tenant = evidence_tenant
        self.rpc_calls = []

    async def select_one(self, table, columns, **filters):
        if table == "service_requests":
            assert filters == {"id": "request-1"}
            return {
                "id": "request-1",
                "organization_id": "org-1",
                "service_key": "dark_web_monitoring",
                "processing_state": "running",
                "target": "owned-example.com",
                "target_type": "domain",
                "attempts": 1,
                "locked_until": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
            }
        if table == "customer_organizations":
            assert filters == {"id": "org-1"}
            return {
                "id": "org-1",
                "tenant_id": "tenant-1",
                "admission_status": "approved",
            }
        assert table == "dw_watchlist"
        assert filters == {"id": "watchlist-1", "tenant_id": "tenant-1"}
        return {
            "id": "watchlist-1",
            "tenant_id": "tenant-1",
            "kind": "domain",
            "value": "owned-example.com",
            "value_hash": hashlib.sha256(b"owned-example.com").hexdigest(),
            "label": "Authorized domain",
        }

    async def rpc(self, function, params):
        self.rpc_calls.append((function, params))
        if function == "trust_register_subject":
            return {"id": "subject-1", "tenant_id": "tenant-1"}
        if function == "dw_record_evidence_if_current_attempt":
            return {
                "id": "evidence-1",
                "tenant_id": self.evidence_tenant,
                "subject_id": params["p_subject_id"],
                "content_uri": params["p_content_uri"],
                "content_hash": params["p_content_hash"],
                "source_id": params["p_source_id"],
            }
        raise AssertionError(function)

    async def _ensure(self):
        return SimpleNamespace(storage=self.storage)


@pytest.mark.asyncio
async def test_target_matched_onion_evidence_uses_tenant_scoped_subject_and_rpc():
    storage = _Storage()
    service = _ServiceClient(storage)
    host = "a" * 56 + ".onion"
    result = await record_target_matched_onion_evidence(
        service,
        tenant_id="tenant-1",
        watchlist_id="watchlist-1",
        service_request_id="request-1",

        expected_attempt=1,
        source_url=f"http://{host}/leak",
        sanitized_page_text="Public page mentions owned-example.com in the body.",
        observed_at="2026-10-22T00:00:00+00:00",
    )
    assert result["readback_sha256_verified"] is True
    assert result["finding_class"] == "candidate_evidence_not_verified"
    fenced_call = service.rpc_calls[-1]
    assert fenced_call[0] == "dw_record_evidence_if_current_attempt"
    assert fenced_call[1]["p_service_request_id"] == "request-1"
    assert fenced_call[1]["p_expected_attempt"] == 1
    assert fenced_call[1]["p_tenant_id"] == "tenant-1"
    assert fenced_call[1]["p_watchlist_id"] == "watchlist-1"
    assert [call[0] for call in service.rpc_calls] == [
        "trust_register_subject", "dw_record_evidence_if_current_attempt"
    ]
    assert service.rpc_calls[-1][1]["p_content_hash"] == result["content_sha256"]


@pytest.mark.asyncio
async def test_target_match_must_be_reproducible_before_subject_creation():
    service = _ServiceClient(_Storage())
    host = "b" * 56 + ".onion"
    with pytest.raises(RuntimeError, match="dw_evidence_target_match_not_reproducible"):
        await record_target_matched_onion_evidence(
            service,
            tenant_id="tenant-1",
            watchlist_id="watchlist-1",
            service_request_id="request-1",

            expected_attempt=1,
            source_url=f"http://{host}/leak",
            sanitized_page_text="No monitored target here.",
            observed_at="2026-10-22T00:00:00+00:00",
        )
    assert service.rpc_calls == []


@pytest.mark.asyncio
async def test_request_tenant_mismatch_fails_before_storage_or_evidence_rpc():
    storage = _Storage()
    service = _ServiceClient(storage)

    async def mismatched_org(table, columns, **filters):
        if table == "service_requests":
            return {
                "id": "request-1",
                "organization_id": "org-1",
                "service_key": "dark_web_monitoring",
                "processing_state": "running",
                "target": "owned-example.com",
                "target_type": "domain",
                "attempts": 1,
                "locked_until": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
            }
        if table == "customer_organizations":
            return {
                "id": "org-1",
                "tenant_id": "another-tenant",
                "admission_status": "approved",
            }
        return None

    service.select_one = mismatched_org
    host = "c" * 56 + ".onion"
    with pytest.raises(RuntimeError, match="dw_evidence_request_tenant_authorization_failed"):
        await record_target_matched_onion_evidence(
            service,
            tenant_id="tenant-1",
            watchlist_id="watchlist-1",
            service_request_id="request-1",

            expected_attempt=1,
            source_url=f"http://{host}/leak",
            sanitized_page_text="Public page mentions owned-example.com in the body.",
            observed_at="2026-10-22T00:00:00+00:00",
        )
    assert storage.bucket.stored is None
    assert service.rpc_calls == []


@pytest.mark.asyncio
async def test_request_watchlist_target_mismatch_fails_before_storage_or_evidence_rpc():
    storage = _Storage()
    service = _ServiceClient(storage)
    original_select_one = service.select_one

    async def mismatched_target(table, columns, **filters):
        row = await original_select_one(table, columns, **filters)
        if table == "service_requests":
            row["target"] = "attacker-example.net"
        return row

    service.select_one = mismatched_target
    host = "d" * 56 + ".onion"
    with pytest.raises(RuntimeError, match="dw_evidence_request_watchlist_target_mismatch"):
        await record_target_matched_onion_evidence(
            service,
            tenant_id="tenant-1",
            watchlist_id="watchlist-1",
            service_request_id="request-1",

            expected_attempt=1,
            source_url=f"http://{host}/leak",
            sanitized_page_text="Public page mentions owned-example.com in the body.",
            observed_at="2026-10-22T00:00:00+00:00",
        )
    assert storage.bucket.stored is None
    assert service.rpc_calls == []


@pytest.mark.asyncio
async def test_trust_evidence_rpc_return_for_wrong_tenant_fails_closed():
    service = _ServiceClient(_Storage(), evidence_tenant="another-tenant")
    host = "e" * 56 + ".onion"
    with pytest.raises(RuntimeError, match="dw_evidence_rpc_returned_unbound_record"):
        await record_target_matched_onion_evidence(
            service,
            tenant_id="tenant-1",
            watchlist_id="watchlist-1",
            service_request_id="request-1",

            expected_attempt=1,
            source_url=f"http://{host}/leak",
            sanitized_page_text="Public page mentions owned-example.com in the body.",
            observed_at="2026-10-22T00:00:00+00:00",
        )
    assert [call[0] for call in service.rpc_calls] == [
        "trust_register_subject", "dw_record_evidence_if_current_attempt"
    ]


@pytest.mark.asyncio
async def test_expired_request_lease_cannot_write_evidence():
    storage = _Storage()
    service = _ServiceClient(storage)
    original_select_one = service.select_one

    async def expired_lease(table, columns, **filters):
        row = await original_select_one(table, columns, **filters)
        if table == "service_requests":
            row["locked_until"] = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
        return row

    service.select_one = expired_lease
    host = "f" * 56 + ".onion"
    with pytest.raises(RuntimeError, match="dw_evidence_request_lease_expired"):
        await record_target_matched_onion_evidence(
            service,
            tenant_id="tenant-1",
            watchlist_id="watchlist-1",
            service_request_id="request-1",
            expected_attempt=1,
            source_url=f"http://{host}/leak",
            sanitized_page_text="Public page mentions owned-example.com in the body.",
            observed_at="2026-10-22T00:00:00+00:00",
        )
    assert storage.bucket.stored is None
    assert service.rpc_calls == []


@pytest.mark.asyncio
async def test_reclaimed_request_attempt_cannot_write_evidence():
    storage = _Storage()
    service = _ServiceClient(storage)
    original_select_one = service.select_one

    async def newer_attempt(table, columns, **filters):
        row = await original_select_one(table, columns, **filters)
        if table == "service_requests":
            row["attempts"] = 2
        return row

    service.select_one = newer_attempt
    host = "g" * 56 + ".onion"
    with pytest.raises(RuntimeError, match="dw_evidence_authorized_running_request_not_found"):
        await record_target_matched_onion_evidence(
            service,
            tenant_id="tenant-1",
            watchlist_id="watchlist-1",
            service_request_id="request-1",
            expected_attempt=1,
            source_url=f"http://{host}/leak",
            sanitized_page_text="Public page mentions owned-example.com in the body.",
            observed_at="2026-10-22T00:00:00+00:00",
        )
    assert storage.bucket.stored is None
    assert service.rpc_calls == []


@pytest.mark.asyncio
async def test_existing_evidence_object_with_different_bytes_fails_closed():
    storage = _Storage()
    storage.bucket.path = "tenant/subject/request/evidence.txt"
    storage.bucket.stored = b"evidence from a different request"
    with pytest.raises(RuntimeError, match="dw_evidence_existing_object_conflicts_with_content"):
        await store_and_verify_evidence(
            storage,
            object_path="tenant/subject/request/evidence.txt",
            sanitized_text="Target example.test",
        )
    assert storage.bucket.stored == b"evidence from a different request"
