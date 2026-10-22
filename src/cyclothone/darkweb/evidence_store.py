from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

MAX_EVIDENCE_BYTES = 512_000
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_BUCKET = "dw-evidence-private"


@dataclass(frozen=True, slots=True)
class StoredEvidence:
    bucket: str
    object_path: str
    sha256: str
    size_bytes: int
    content_type: str = "text/plain; charset=utf-8"


def _safe_segment(value: str) -> str:
    value = str(value or "").strip()
    if not value or len(value) > 128 or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("dw_evidence_invalid_path_segment")
    return value


def evidence_object_path(*, tenant_id: str, subject_id: str, request_id: str, evidence_id: str) -> str:
    """Build a non-public object key from validated opaque identifiers."""
    return "/".join((
        _safe_segment(tenant_id),
        _safe_segment(subject_id),
        _safe_segment(request_id),
        _safe_segment(evidence_id) + ".txt",
    ))


async def store_and_verify_evidence(
    storage_client: Any,
    *,
    object_path: str,
    sanitized_text: str,
    max_bytes: int = MAX_EVIDENCE_BYTES,
) -> StoredEvidence:
    """Upload sanitized UTF-8 evidence, read it back, and verify exact-byte integrity.

    The caller is responsible for sanitization, tenant authorization, and subject
    resolution. This function deliberately does not create trust subjects or write
    trust-evidence rows, and never treats a successful upload as a verified finding.
    """
    if not object_path or object_path.startswith("/") or ".." in object_path.split("/"):
        raise ValueError("dw_evidence_invalid_object_path")
    if max_bytes < 1 or max_bytes > MAX_EVIDENCE_BYTES:
        raise ValueError("dw_evidence_invalid_size_limit")
    if not isinstance(sanitized_text, str) or not sanitized_text.strip():
        raise ValueError("dw_evidence_empty_content")

    content = sanitized_text.encode("utf-8")
    if len(content) > max_bytes:
        raise ValueError("dw_evidence_content_too_large")
    digest = hashlib.sha256(content).hexdigest()
    bucket = storage_client.from_(_BUCKET)
    await bucket.upload(
        object_path,
        content,
        file_options={"content-type": "text/plain; charset=utf-8", "upsert": "false"},
    )
    response = await bucket.download(object_path)
    if not isinstance(response, (bytes, bytearray)):
        raise RuntimeError("dw_evidence_readback_invalid_type")
    readback = bytes(response)
    readback_digest = hashlib.sha256(readback).hexdigest()
    if readback != content or not _SHA256_RE.fullmatch(readback_digest) or readback_digest != digest:
        raise RuntimeError("dw_evidence_readback_integrity_mismatch")
    return StoredEvidence(
        bucket=_BUCKET,
        object_path=object_path,
        sha256=digest,
        size_bytes=len(content),
    )
