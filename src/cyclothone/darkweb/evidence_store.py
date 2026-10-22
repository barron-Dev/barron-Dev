from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

MAX_EVIDENCE_BYTES = 512_000
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_BUCKET = "dw-evidence-private"
_ONION_V3 = re.compile(r"^[a-z2-7]{56}\.onion$", re.IGNORECASE)


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
    resolution. This function does not classify findings as verified.
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
    try:
        await bucket.upload(
            object_path,
            content,
            file_options={"content-type": "text/plain", "upsert": "false"},
        )
    except Exception as upload_error:
        # A timeout can happen after the object was committed. Treat that as a
        # retry only when the deterministic key already contains the exact bytes.
        try:
            existing = await bucket.download(object_path)
        except Exception:
            raise upload_error
        if not isinstance(existing, (bytes, bytearray)) or bytes(existing) != content:
            raise RuntimeError("dw_evidence_existing_object_conflicts_with_content") from upload_error

    response = await bucket.download(object_path)
    if not isinstance(response, (bytes, bytearray)):
        raise RuntimeError("dw_evidence_readback_invalid_type")
    readback = bytes(response)
    readback_digest = hashlib.sha256(readback).hexdigest()
    if readback != content or not _SHA256_RE.fullmatch(readback_digest) or readback_digest != digest:
        raise RuntimeError("dw_evidence_readback_integrity_mismatch")
    return StoredEvidence(_BUCKET, object_path, digest, len(content))


def _validate_public_onion_url(source_url: str) -> str:
    parsed = urlsplit(source_url)
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme not in {"http", "https"} or not _ONION_V3.fullmatch(host):
        raise ValueError("dw_evidence_source_not_public_v3_onion")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("dw_evidence_source_url_invalid") from exc
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("dw_evidence_source_url_invalid")
    if port is not None and port not in {80, 443}:
        raise ValueError("dw_evidence_source_url_invalid")
    return source_url


async def record_target_matched_onion_evidence(
    service_client: Any,
    *,
    tenant_id: str,
    watchlist_id: str,
    service_request_id: str,
    source_url: str,
    sanitized_page_text: str,
    observed_at: str,
) -> dict[str, Any]:
    """Persist matched page bytes and link them to existing tenant-scoped trust evidence.

    The caller must invoke this only after the worker has authorized the request.
    Target identity is reloaded from dw_watchlist under the supplied tenant ID;
    the caller cannot supply or override the target value.
    """
    _validate_public_onion_url(source_url)

    # Resolve the request's tenant through the live organization relationship;
    # a caller-supplied tenant UUID alone is not authorization.
    request = await service_client.select_one(
        "service_requests",
        "id,organization_id,service_key,processing_state,target,target_type",
        id=service_request_id,
    )
    if (
        not request
        or str(request.get("id")) != str(service_request_id)
        or request.get("service_key") != "dark_web_monitoring"
        or request.get("processing_state") != "running"
    ):
        raise RuntimeError("dw_evidence_authorized_running_request_not_found")

    organization = await service_client.select_one(
        "customer_organizations",
        "id,tenant_id,admission_status",
        id=str(request.get("organization_id") or ""),
    )
    if (
        not organization
        or organization.get("admission_status") != "approved"
        or str(organization.get("tenant_id")) != str(tenant_id)
    ):
        raise RuntimeError("dw_evidence_request_tenant_authorization_failed")

    target = await service_client.select_one(
        "dw_watchlist", "id,tenant_id,kind,value,value_hash,label",
        id=watchlist_id, tenant_id=tenant_id,
    )
    if not target or str(target.get("tenant_id")) != str(tenant_id):
        raise RuntimeError("dw_evidence_authorized_watchlist_target_not_found")

    from cyclothone.darkweb.native_onion import _target_pattern, normalize, sanitize_target_matched_excerpt

    request_type = str(request.get("target_type") or "").strip().lower()
    request_target = str(request.get("target") or "").strip()
    expected_kind = {
        "domain": "domain", "url": "domain", "email": "email", "brand": "company_name",
        "username": "username", "ip": "ip", "other": "other",
    }.get(request_type)
    if request_type in {"domain", "url"}:
        parsed_target = urlsplit(request_target if "://" in request_target else f"https://{request_target}")
        expected_value = (parsed_target.hostname or "").lower().rstrip(".")
    else:
        expected_value = normalize(request_target)
    kind = str(target.get("kind") or "")
    value = str(target.get("value") or "")
    if not expected_kind or kind != expected_kind or normalize(value) != expected_value:
        raise RuntimeError("dw_evidence_request_watchlist_target_mismatch")
    pattern = _target_pattern(kind, value)
    evidence_text = sanitize_target_matched_excerpt(sanitized_page_text, pattern)
    if not evidence_text or not pattern.search(evidence_text):
        raise RuntimeError("dw_evidence_target_match_not_reproducible")

    subject = await service_client.rpc("trust_register_subject", {
        "p_tenant_id": tenant_id,
        "p_subject_kind": "dark_web_monitoring_target",
        "p_external_ref": str(target["id"]),
        "p_display_name": str(target.get("label") or target["id"])[:200],
        "p_provider_id": "cyclothone",
        "p_version": "dw-evidence-v1",
        "p_identity_document": {
            "watchlist_id": str(target["id"]),
            "target_kind": kind,
            "target_value_hash": str(target.get("value_hash") or hashlib.sha256(normalize(value).encode()).hexdigest()),
        },
        "p_public_key_algorithm": None,
        "p_public_key": None,
        "p_key_id": None,
        "p_created_by": None,
    })
    if isinstance(subject, list):
        subject = subject[0] if subject else None
    if not isinstance(subject, dict) or not subject.get("id") or str(subject.get("tenant_id")) != str(tenant_id):
        raise RuntimeError("dw_evidence_subject_registration_invalid")

    subject_id = str(subject["id"])
    content_hash = hashlib.sha256(evidence_text.encode("utf-8")).hexdigest()
    object_path = evidence_object_path(
        tenant_id=tenant_id,
        subject_id=subject_id,
        request_id=service_request_id,
        evidence_id=content_hash,
    )
    client = await service_client._ensure()
    stored = await store_and_verify_evidence(
        client.storage,
        object_path=object_path,
        sanitized_text=evidence_text,
    )
    # A separate retrieval repeats both integrity and target-match checks.
    readback = await client.storage.from_(stored.bucket).download(stored.object_path)
    if not isinstance(readback, (bytes, bytearray)):
        raise RuntimeError("dw_evidence_independent_readback_invalid_type")
    readback_bytes = bytes(readback)
    if hashlib.sha256(readback_bytes).hexdigest() != stored.sha256:
        raise RuntimeError("dw_evidence_independent_readback_hash_mismatch")
    try:
        readback_text = readback_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError("dw_evidence_independent_readback_not_utf8") from exc
    if not pattern.search(readback_text):
        raise RuntimeError("dw_evidence_independent_target_match_failed")
    uri = f"supabase://{stored.bucket}/{stored.object_path}"
    evidence = await service_client.rpc("trust_record_evidence", {
        "p_subject_id": subject_id,
        "p_evidence_type": "dark_web_page_match",
        "p_source_type": "native_onion",
        "p_source_id": source_url,
        "p_content_type": stored.content_type,
        "p_content_uri": uri,
        "p_content_hash": stored.sha256,
        "p_collected_at": observed_at,
        "p_expires_at": None,
        "p_signature_algorithm": None,
        "p_signer_key_id": None,
        "p_signature": None,
        "p_metadata": {
            "tenant_id": str(tenant_id),
            "watchlist_id": str(target["id"]),
            "service_request_id": str(service_request_id),
            "source_url": source_url,
            "content_bytes": stored.size_bytes,
            "evidence_scope": "bounded_match_excerpt",
            "readback_sha256_verified": True,
            "classification": "candidate_evidence_not_verified_finding",
        },
    })
    return {
        "subject_id": subject_id,
        "evidence": evidence,
        "content_uri": uri,
        "content_sha256": stored.sha256,
        "readback_sha256_verified": True,
        "finding_class": "candidate_evidence_not_verified",
    }
