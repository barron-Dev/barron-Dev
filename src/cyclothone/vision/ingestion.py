"""Bounded raw-media ingestion boundary for Omni-Vision.

Hashes exact uploaded bytes before decoding or re-encoding. This is deliberately not a
storage adapter: callers must persist the returned receipt through an authenticated,
tenant-scoped durable backend before treating ingestion as complete.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import re


@dataclass(frozen=True, slots=True)
class MediaReceipt:
    tenant_id: str
    source_id: str
    modality: str
    media_sha256: str
    byte_length: int
    detected_format: str
    declared_content_type: str
    ingestion_status: str
    coverage_gaps: tuple[str, ...]


_MAGIC = (
    (b"\xff\xd8\xff", "jpeg", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "png", "image/png"),
    (b"RIFF", "riff_container", None),
    (b"%PDF-", "pdf", "application/pdf"),
    (b"OggS", "ogg", "audio/ogg"),
    (b"fLaC", "flac", "audio/flac"),
    (b"ID3", "mp3", "audio/mpeg"),
)
_HASH = re.compile(r"^[0-9a-f]{64}$")


def _detect_format(data: bytes) -> tuple[str, str | None]:
    for magic, fmt, content_type in _MAGIC:
        if data.startswith(magic):
            if fmt == "riff_container":
                if len(data) >= 12 and data[8:12] == b"WAVE":
                    return "wav", "audio/wav"
                return "riff_container", None
            return fmt, content_type
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return "mp4", "video/mp4"
    return "unknown", None


def ingest_media_bytes(*, tenant_id: str, source_id: str, modality: str,
                       media: bytes, content_type: str, max_bytes: int = 25_000_000) -> MediaReceipt:
    """Validate tenant-scoped metadata and hash real source bytes without decoding."""
    if not isinstance(tenant_id, str) or not tenant_id.strip() or len(tenant_id) > 200:
        raise ValueError("invalid_tenant_id")
    if not isinstance(source_id, str) or not source_id.strip() or len(source_id) > 200:
        raise ValueError("invalid_source_id")
    if modality not in {"cam", "file", "audio", "doc", "env"}:
        raise ValueError("unsupported_modality")
    if not isinstance(media, bytes):
        raise TypeError("media_must_be_bytes")
    if not isinstance(content_type, str) or "/" not in content_type or len(content_type) > 128:
        raise ValueError("invalid_content_type")
    if not 1 <= max_bytes <= 250_000_000:
        raise ValueError("invalid_max_bytes")
    if not media:
        raise ValueError("empty_media")
    if len(media) > max_bytes:
        raise ValueError("media_exceeds_size_limit")
    fmt, detected_type = _detect_format(media)
    if fmt == "unknown":
        raise ValueError("unsupported_or_unrecognized_media_format")
    gaps = []
    if detected_type is None:
        gaps.append("container_not_fully_identified")
    elif content_type.split(";", 1)[0].strip().lower() != detected_type:
        raise ValueError("content_type_magic_mismatch")
    # Receipt hashes the exact byte sequence; it does not assert source authenticity.
    return MediaReceipt(tenant_id.strip(), source_id.strip(), modality,
                        hashlib.sha256(media).hexdigest(), len(media), fmt,
                        content_type, "validated_not_persisted", tuple(gaps))
