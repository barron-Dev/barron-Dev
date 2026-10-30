from __future__ import annotations

import io
import json
import os
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, File, Header, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from fastapi.concurrency import run_in_threadpool

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.api.routes.customer_identity import principal as customer_or_developer_principal
from cyclothone.provenance.c2pa_verify import ZERO_HASH, build_receipt_hash, sign_receipt, validate_trust_policy, verify_c2pa_file
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/media", tags=["synthetic-media-provenance"])


async def provenance_principal(
    authorization: str | None = Header(None),
    x_api_key: str | None = Header(None),
) -> DeveloperPrincipal:
    try:
        return await authenticate_request(authorization=authorization, x_api_key=x_api_key)
    except HTTPException as exc:
        if exc.status_code != 401:
            raise
        return await customer_or_developer_principal(authorization=authorization)


def _require_access(principal: DeveloperPrincipal) -> None:
    if principal.auth_type == "customer":
        principal.require(("console:read",))
    else:
        principal.require(("media:provenance:verify",))
MAX_UPLOAD_BYTES = int(os.getenv("CYCLOTHONE_PROVENANCE_MAX_UPLOAD_BYTES", str(250 * 1024 * 1024)))


@router.post("/verify-provenance")
async def verify_provenance(
    file: UploadFile = File(...),
    principal: DeveloperPrincipal = Depends(provenance_principal),
):
    _require_access(principal)
    tenant_id = str(UUID(principal.tenant_id))
    policy = await supabase.select_one(
        "c2pa_trust_policies",
        "id,policy_name,policy_version,trusted_root_pems,trusted_root_sha256",
        is_active=True,
    )
    if not policy or not policy.get("trusted_root_pems"):
        raise HTTPException(503, {"error": "trust_policy_unavailable", "message": "No active versioned C2PA trust policy is configured."})

    suffix = Path(file.filename or "").suffix[:16]
    size = 0
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(prefix="cyclothone-c2pa-", suffix=suffix, delete=False) as tmp:
            temp_path = tmp.name
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, {"error": "media_too_large", "max_bytes": MAX_UPLOAD_BYTES})
                tmp.write(chunk)
        if size == 0:
            raise HTTPException(400, {"error": "empty_media"})
        anchors = "\n".join(policy["trusted_root_pems"])
        result = await run_in_threadpool(verify_c2pa_file, temp_path, anchors)
    finally:
        await file.close()
        if temp_path:
            Path(temp_path).unlink(missing_ok=True)

    created_at = datetime.now(timezone.utc).isoformat()
    ml_assessment = {"status": "not_requested", "influences_cryptographic_state": False}
    client = await supabase._ensure()
    head_response = await client.table("media_provenance_receipts").select("receipt_hash").eq("tenant_id", tenant_id).order("created_at", desc=True).order("id", desc=True).limit(1).execute()
    head_rows = head_response.data or []
    previous_hash = head_rows[0]["receipt_hash"] if head_rows else ZERO_HASH
    receipt_payload = {
        "tenant_id": tenant_id, "media_sha256": result.media_sha256,
        "manifest_store_sha256": result.manifest_store_sha256,
        "validation_state": result.validation_state, "signer_identity": result.signer_identity,
        "trust_policy_id": policy["id"], "trust_policy_version": policy["policy_version"],
        "sdk_version": result.sdk_version, "previous_receipt_hash": previous_hash,
        "created_at": created_at, "ml_assessment": ml_assessment,
    }
    receipt_hash = build_receipt_hash(receipt_payload)
    try:
        signature, signing_key_id, signing_public_key = sign_receipt(receipt_payload)
    except RuntimeError as exc:
        raise HTTPException(503, {"error": "receipt_signing_unavailable", "message": str(exc)}) from exc

    rpc_args = {
        "p_tenant_id": tenant_id, "p_media_sha256": result.media_sha256,
        "p_manifest_store_sha256": result.manifest_store_sha256,
        "p_validation_state": result.validation_state, "p_signer_identity": result.signer_identity,
        "p_trust_policy_id": policy["id"], "p_trust_policy_version": policy["policy_version"],
        "p_sdk_version": result.sdk_version, "p_raw_c2pa_report": result.report,
        "p_ml_assessment": ml_assessment, "p_previous_receipt_hash": previous_hash,
        "p_receipt_hash": receipt_hash, "p_receipt_signature": signature,
        "p_signing_key_id": signing_key_id, "p_signing_public_key": signing_public_key,
        "p_signed_payload": receipt_payload,
    }
    try:
        receipt_id = await supabase.rpc("append_media_provenance_receipt", rpc_args)
    except Exception as exc:
        raise HTTPException(503, {"error": "receipt_persistence_failed", "message": "Verification completed but the signed receipt was not persisted."}) from exc

    return {
        "receipt_id": str(receipt_id), "validation_state": result.validation_state,
        "media_sha256": result.media_sha256, "manifest_store_sha256": result.manifest_store_sha256,
        "signer": result.signer_identity, "trust_policy": policy["policy_name"],
        "trust_policy_version": policy["policy_version"], "sdk_version": result.sdk_version,
        "receipt_hash": receipt_hash, "cryptographic_proof": {"algorithm": "Ed25519", "signature": signature, "key_id": signing_key_id, "public_key": signing_public_key},
        "ml_assessment": ml_assessment,
        "disposition": result.validation_state,
        "interpretation_limit": "C2PA provenance does not prove depicted identity, scene truth, or signer authorization beyond the configured certificate trust policy.",
    }



@router.get("/receipts")
async def list_provenance_receipts(principal: DeveloperPrincipal = Depends(authenticate_request)):
    _require_access(principal)
    tenant_id = str(UUID(principal.tenant_id))
    client = await supabase._ensure()
    response = await client.table("media_provenance_receipts").select(
        "id,media_sha256,manifest_store_sha256,validation_state,signer_identity,trust_policy_version,receipt_hash,created_at"
    ).eq("tenant_id", tenant_id).order("created_at", desc=True).limit(100).execute()
    return response.data or []


@router.get("/receipts/{receipt_id}/bundle")
async def download_provenance_bundle(receipt_id: UUID, principal: DeveloperPrincipal = Depends(authenticate_request)):
    _require_access(principal)
    tenant_id = str(UUID(principal.tenant_id))
    client = await supabase._ensure()
    response = await client.table("media_provenance_receipts").select("*").eq(
        "tenant_id", tenant_id
    ).eq("id", str(receipt_id)).limit(1).execute()
    rows = response.data or []
    if not rows:
        raise HTTPException(404, {"error": "receipt_not_found"})
    row = rows[0]
    bundle = io.BytesIO()
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("receipt.json", json.dumps({
            "receipt_id": row["id"], "tenant_id": row["tenant_id"],
            "media_sha256": row["media_sha256"],
            "manifest_store_sha256": row["manifest_store_sha256"],
            "validation_state": row["validation_state"],
            "trust_policy_version": row["trust_policy_version"],
            "previous_receipt_hash": row["previous_receipt_hash"],
            "receipt_hash": row["receipt_hash"],
            "signed_payload": row["signed_payload"],
            "signature": row["receipt_signature"],
            "signature_algorithm": "Ed25519",
            "signing_key_id": row["signing_key_id"],
            "signing_public_key": row["signing_public_key"],
            "created_at": row["created_at"],
        }, sort_keys=True, indent=2))
        archive.writestr("c2pa-report.json", json.dumps(row["raw_c2pa_report"], sort_keys=True, indent=2))
        if isinstance(row["raw_c2pa_report"], dict) and row["raw_c2pa_report"].get("manifest"):
            archive.writestr("active-manifest.json", json.dumps(row["raw_c2pa_report"]["manifest"], sort_keys=True, indent=2))
    bundle.seek(0)
    return StreamingResponse(
        bundle, media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="cyclothone-{receipt_id}.ctprove"'},
    )
