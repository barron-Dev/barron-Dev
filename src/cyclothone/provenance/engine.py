from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cyclothone.provenance.c2pa_verify import (
    ZERO_HASH, build_receipt_hash, canonical_json, sign_receipt,
    validate_trust_policy, verify_c2pa_file,
)
from cyclothone.storage.supabase_client import supabase


class PermanentProvenanceError(RuntimeError):
    """A configuration or policy error that should not be retried by the worker."""


async def _result_from_receipt(row: dict[str, Any]) -> dict[str, Any]:
    policy = await supabase.select_one(
        "c2pa_trust_policies", "policy_name", id=str(row["trust_policy_id"])
    )
    return {
        "receipt_id": str(row["id"]),
        "validation_state": row["validation_state"],
        "media_sha256": row["media_sha256"],
        "manifest_store_sha256": row["manifest_store_sha256"],
        "signer": row["signer_identity"],
        "trust_policy": policy.get("policy_name") if policy else None,
        "trust_policy_version": row["trust_policy_version"],
        "sdk_version": row["sdk_version"],
        "receipt_hash": row["receipt_hash"],
        "cryptographic_proof": {
            "algorithm": "Ed25519",
            "signature": row["receipt_signature"],
            "key_id": row["signing_key_id"],
            "public_key": row["signing_public_key"],
        },
        "ml_assessment": row["ml_assessment"],
        "disposition": row["validation_state"],
        "interpretation_limit": (
            "C2PA provenance does not prove depicted identity, scene truth, or signer authorization "
            "beyond the configured certificate trust policy. Revocation checking is not performed."
        ),
    }


async def verify_and_persist_media(
    tenant_id: str, file_path: str | Path, source_job_id: str
) -> dict[str, Any]:
    existing = await supabase.select_one(
        "media_provenance_receipts", "*",
        tenant_id=tenant_id, source_job_id=source_job_id,
    )
    if existing:
        return await _result_from_receipt(existing)

    policy = await supabase.select_one(
        "c2pa_trust_policies",
        "id,policy_name,policy_version,trusted_anchor_pems,trusted_anchor_sha256,tsa_anchor_pems,tsa_anchor_sha256,source_uri,source_commit,source_sha256,source_issued_at,source_next_update",
        is_active=True,
    )
    if not policy or not policy.get("trusted_anchor_pems") or not policy.get("tsa_anchor_pems"):
        raise PermanentProvenanceError("trust_policy_unavailable")
    policy_expiry = datetime.fromisoformat(str(policy["source_next_update"]).replace("Z", "+00:00"))
    if policy_expiry <= datetime.now(timezone.utc):
        raise PermanentProvenanceError("trust_policy_expired")

    try:
        manifest_anchors = validate_trust_policy(policy["trusted_anchor_pems"], policy["trusted_anchor_sha256"])
        tsa_anchors = validate_trust_policy(policy["tsa_anchor_pems"], policy["tsa_anchor_sha256"])
    except (ValueError, TypeError) as exc:
        raise PermanentProvenanceError("trust_policy_invalid") from exc
    source_uris = str(policy["source_uri"]).splitlines()
    if len(source_uris) != 2:
        raise PermanentProvenanceError("trust_policy_source_invalid")
    result = await asyncio.to_thread(
        verify_c2pa_file, file_path, manifest_anchors, tsa_anchors, source_uris[0], source_uris[1]
    )
    ml_assessment = {"status": "not_requested", "influences_cryptographic_state": False}
    client = await supabase._ensure()

    receipt_id = None
    for attempt in range(3):
        head_response = await client.table("media_provenance_receipts").select("receipt_hash").eq(
            "tenant_id", tenant_id
        ).order("tenant_sequence", desc=True).limit(1).execute()
        head_rows = head_response.data or []
        previous_hash = head_rows[0]["receipt_hash"] if head_rows else ZERO_HASH
        created_at = datetime.now(timezone.utc).isoformat()
        receipt_payload = {
            "source_job_id": source_job_id,
            "tenant_id": tenant_id,
            "media_sha256": result.media_sha256,
            "manifest_store_sha256": result.manifest_store_sha256,
            "validation_state": result.validation_state,
            "signer_identity": result.signer_identity,
            "trust_policy_id": policy["id"],
            "trust_policy_version": policy["policy_version"],
            "trust_policy_source_uri": policy["source_uri"],
            "trust_policy_source_commit": policy["source_commit"],
            "trust_policy_source_sha256": str(policy["source_sha256"]).strip(),
            "trust_policy_source_issued_at": datetime.fromisoformat(str(policy["source_issued_at"]).replace("Z", "+00:00")).isoformat(),
            "trust_policy_source_next_update": datetime.fromisoformat(str(policy["source_next_update"]).replace("Z", "+00:00")).isoformat(),
            "sdk_version": result.sdk_version,
            "previous_receipt_hash": previous_hash,
            "created_at": created_at,
            "ml_assessment": ml_assessment,
        }
        receipt_hash = build_receipt_hash(receipt_payload)
        try:
            signature, signing_key_id, signing_public_key = sign_receipt(receipt_payload)
        except (RuntimeError, ValueError, TypeError) as exc:
            raise PermanentProvenanceError("receipt_signing_unavailable") from exc

        rpc_args = {
            "p_source_job_id": source_job_id,
            "p_tenant_id": tenant_id,
            "p_media_sha256": result.media_sha256,
            "p_manifest_store_sha256": result.manifest_store_sha256,
            "p_validation_state": result.validation_state,
            "p_signer_identity": result.signer_identity,
            "p_trust_policy_id": policy["id"],
            "p_trust_policy_version": policy["policy_version"],
            "p_sdk_version": result.sdk_version,
            "p_raw_c2pa_report": result.report,
            "p_ml_assessment": ml_assessment,
            "p_previous_receipt_hash": previous_hash,
            "p_receipt_hash": receipt_hash,
            "p_receipt_signature": signature,
            "p_signing_key_id": signing_key_id,
            "p_signing_public_key": signing_public_key,
            "p_signed_payload": receipt_payload,
            "p_signed_payload_canonical": canonical_json(receipt_payload).decode("utf-8"),
        }
        try:
            receipt_id = await supabase.rpc("append_media_provenance_receipt", rpc_args)
            break
        except Exception as exc:
            conflict = "receipt chain head changed" in str(exc).lower() or "40001" in str(exc)
            if conflict and attempt < 2:
                continue
            if conflict:
                raise RuntimeError("receipt_chain_busy") from exc
            raise

    if receipt_id is None:
        raise RuntimeError("receipt_persistence_failed")
    persisted = await supabase.select_one(
        "media_provenance_receipts", "*",
        id=str(receipt_id), tenant_id=tenant_id,
    )
    if not persisted:
        raise RuntimeError("receipt_persistence_unconfirmed")
    return await _result_from_receipt(persisted)
