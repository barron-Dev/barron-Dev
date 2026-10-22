import hashlib

import pytest

from cyclothone.darkweb.evidence_store import (
    MAX_EVIDENCE_BYTES,
    evidence_object_path,
    store_and_verify_evidence,
)


class _Bucket:
    def __init__(self, tamper=False):
        self.stored = None
        self.tamper = tamper
        self.upload_options = None
        self.path = None

    async def upload(self, path, content, file_options=None):
        self.path = path
        self.stored = bytes(content)
        self.upload_options = file_options

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
