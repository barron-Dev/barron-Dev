import hashlib
import pytest
from cyclothone.vision.ingestion import ingest_media_bytes


PNG = b"\x89PNG\r\n\x1a\n" + b"payload"


def test_ingestion_hashes_exact_original_bytes():
    receipt = ingest_media_bytes(tenant_id="tenant-a", source_id="camera-1",
                                 modality="cam", media=PNG, content_type="image/png")
    assert receipt.media_sha256 == hashlib.sha256(PNG).hexdigest()
    assert receipt.byte_length == len(PNG)
    assert receipt.ingestion_status == "validated_not_persisted"


def test_content_type_must_match_magic_bytes():
    with pytest.raises(ValueError, match="content_type_magic_mismatch"):
        ingest_media_bytes(tenant_id="t", source_id="s", modality="file",
                           media=PNG, content_type="image/jpeg")


def test_unknown_media_is_rejected_not_guessed():
    with pytest.raises(ValueError, match="unsupported_or_unrecognized_media_format"):
        ingest_media_bytes(tenant_id="t", source_id="s", modality="file",
                           media=b"random bytes", content_type="application/octet-stream")


def test_empty_and_oversized_media_rejected():
    with pytest.raises(ValueError, match="empty_media"):
        ingest_media_bytes(tenant_id="t", source_id="s", modality="file",
                           media=b"", content_type="image/png")
    with pytest.raises(ValueError, match="media_exceeds_size_limit"):
        ingest_media_bytes(tenant_id="t", source_id="s", modality="file",
                           media=PNG, content_type="image/png", max_bytes=4)


def test_tenant_metadata_is_required():
    with pytest.raises(ValueError, match="invalid_tenant_id"):
        ingest_media_bytes(tenant_id="", source_id="s", modality="file",
                           media=PNG, content_type="image/png")
