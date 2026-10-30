from __future__ import annotations

import io
import json
import os
import zipfile
from pathlib import Path
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, File, Header, HTTPException, UploadFile
from fastapi.responses import StreamingResponse

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.api.routes.customer_identity import principal as customer_or_developer_principal
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/media", tags=["synthetic-media-provenance"])
BUCKET = "cyclothone-provenance-staging"
MAX_UPLOAD_BYTES = int(os.getenv("CYCLOTHONE_PROVENANCE_MAX_UPLOAD_BYTES", str(250 * 1024 * 1024)))


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


def _tenant_uuid(principal: DeveloperPrincipal) -> str:
    if not principal.tenant_id:
        raise HTTPException(403, {"error": "tenant_required"})
    try:
        return str(UUID(principal.tenant_id))
    except ValueError as exc:
        raise HTTPException(403, {"error": "invalid_tenant_context"}) from exc


def _assert_active_policy(policy: dict | None) -> None:
    if not policy or not policy.get("trusted_anchor_pems"):
        raise HTTPException(503, {"error": "trust_policy_unavailable", "message": "No active versioned C2PA trust policy is configured."})
    from datetime import datetime, timezone
    expiry = datetime.fromisoformat(str(policy["source_next_update"]).replace("Z", "+00:00"))
    if expiry <= datetime.now(timezone.utc):
        raise HTTPException(503, {"error": "trust_policy_expired", "message": "The active official C2PA trust-list snapshot has expired."})


@router.post("/verify-provenance", status_code=202)
async def verify_provenance(
    file: UploadFile = File(...),
    principal: DeveloperPrincipal = Depends(provenance_principal),
):
    _require_access(principal)
    tenant_id = _tenant_uuid(principal)
    policy = await supabase.select_one(
        "c2pa_trust_policies",
        "id,policy_name,policy_version,trusted_anchor_pems,trusted_anchor_sha256,source_next_update",
        is_active=True,
    )
    _assert_active_policy(policy)

    filename = Path(file.filename or "media.bin").name[:255]
    suffix = Path(filename).suffix[:16]
    content_type = file.content_type or "application/octet-stream"
    size = 0
    try:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                raise HTTPException(413, {"error": "media_too_large", "max_bytes": MAX_UPLOAD_BYTES})
        if size == 0:
            raise HTTPException(400, {"error": "empty_media"})
        await file.seek(0)

        job_id = str(uuid4())
        object_path = f"{tenant_id}/{job_id}{suffix}"
        client = await supabase._ensure()
        try:
            await client.storage.from_(BUCKET).upload(
                object_path,
                file.file,
                {"content-type": content_type, "upsert": "false"},
            )
        except Exception as exc:
            raise HTTPException(503, {"error": "media_staging_failed", "message": "The private media staging upload did not complete."}) from exc

        requested_by = None
        if principal.user_id:
            try:
                requested_by = str(UUID(str(principal.user_id)))
            except ValueError:
                requested_by = None
        try:
            await supabase.insert_one("media_provenance_jobs", {
                "id": job_id,
                "tenant_id": tenant_id,
                "requested_by": requested_by,
                "object_path": object_path,
                "original_filename": filename,
                "content_type": content_type,
                "status": "queued",
            })
        except Exception as exc:
            try:
                await client.storage.from_(BUCKET).remove([object_path])
            except Exception:
                pass
            raise HTTPException(503, {"error": "verification_queue_unavailable"}) from exc
    finally:
        await file.close()

    return {
        "job_id": job_id,
        "status": "queued",
        "status_url": f"/api/v1/media/jobs/{job_id}",
        "message": "Media securely staged for asynchronous C2PA verification.",
    }


@router.get("/jobs/{job_id}")
async def get_provenance_job(
    job_id: UUID,
    principal: DeveloperPrincipal = Depends(provenance_principal),
):
    _require_access(principal)
    tenant_id = _tenant_uuid(principal)
    job = await supabase.select_one(
        "media_provenance_jobs",
        "id,status,attempts,receipt_id,validation_state,result_json,failure_code,created_at,updated_at,completed_at",
        id=str(job_id),
        tenant_id=tenant_id,
    )
    if not job:
        raise HTTPException(404, {"error": "job_not_found"})
    return {
        "job_id": job["id"],
        "status": job["status"],
        "attempts": job["attempts"],
        "receipt_id": job.get("receipt_id"),
        "validation_state": job.get("validation_state"),
        "result": job.get("result_json"),
        "failure_code": job.get("failure_code"),
        "created_at": job.get("created_at"),
        "completed_at": job.get("completed_at"),
    }


@router.get("/receipts")
async def list_provenance_receipts(principal: DeveloperPrincipal = Depends(provenance_principal)):
    _require_access(principal)
    tenant_id = _tenant_uuid(principal)
    client = await supabase._ensure()
    response = await client.table("media_provenance_receipts").select(
        "id,tenant_sequence,media_sha256,manifest_store_sha256,validation_state,signer_identity,trust_policy_version,receipt_hash,created_at"
    ).eq("tenant_id", tenant_id).order("tenant_sequence", desc=True).limit(100).execute()
    return response.data or []


@router.get("/receipts/{receipt_id}/bundle")
async def download_provenance_bundle(
    receipt_id: UUID,
    principal: DeveloperPrincipal = Depends(provenance_principal),
):
    _require_access(principal)
    tenant_id = _tenant_uuid(principal)
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
            "receipt_id": row["id"],
            "tenant_id": row["tenant_id"],
            "tenant_sequence": row["tenant_sequence"],
            "media_sha256": row["media_sha256"],
            "manifest_store_sha256": row["manifest_store_sha256"],
            "validation_state": row["validation_state"],
            "trust_policy_version": row["trust_policy_version"],
            "previous_receipt_hash": row["previous_receipt_hash"],
            "receipt_hash": row["receipt_hash"],
            "signed_payload": row["signed_payload"],
            "signed_payload_canonical": row["signed_payload_canonical"],
            "signature": row["receipt_signature"],
            "signature_algorithm": "Ed25519",
            "signing_key_id": row["signing_key_id"],
            "signing_public_key": row["signing_public_key"],
            "created_at": row["created_at"],
        }, sort_keys=True, indent=2))
        archive.writestr("c2pa-report.json", json.dumps(row["raw_c2pa_report"], sort_keys=True, indent=2))
        if isinstance(row["raw_c2pa_report"], dict) and row["raw_c2pa_report"].get("manifest_store"):
            archive.writestr("manifest-store.json", json.dumps(row["raw_c2pa_report"]["manifest_store"], sort_keys=True, indent=2))
        if isinstance(row["raw_c2pa_report"], dict) and row["raw_c2pa_report"].get("manifest"):
            archive.writestr("active-manifest.json", json.dumps(row["raw_c2pa_report"]["manifest"], sort_keys=True, indent=2))
    bundle.seek(0)
    return StreamingResponse(
        bundle,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="cyclothone-{receipt_id}.ctprove"'},
    )
