from __future__ import annotations

from datetime import UTC, datetime
from fastapi import APIRouter, Depends, HTTPException

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.recovery.service import create_full_snapshot
from cyclothone.recovery.storage import recovery_storage
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/assurance", tags=["recovery"])


def _principal(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("console:read",))
    return principal


async def _count(table: str, tenant_id: str) -> int:
    async def _do():
        return await (
            await supabase._ensure()
        ).table(table).select("id", count="exact", head=True).eq("tenant_id", tenant_id).execute()

    result = await supabase._retry(_do, attempts=2)
    return int(result.count or 0)


async def _latest(table: str, tenant_id: str, columns: str) -> dict | None:
    async def _do():
        return await (
            await supabase._ensure()
        ).table(table).select(columns).eq("tenant_id", tenant_id).order("created_at", desc=True).limit(1).execute()

    rows = list((await supabase._retry(_do, attempts=2)).data or [])
    return dict(rows[0]) if rows else None


@router.get("/recovery")
async def recovery_status(principal: DeveloperPrincipal = Depends(_principal)) -> dict:
    tenant_id = principal.tenant_id

    policy_count = await _count("recovery_vault_policies", tenant_id)
    snapshot_count = await _count("recovery_snapshots", tenant_id)
    object_count = await _count("recovery_objects", tenant_id)
    restore_job_count = await _count("recovery_restore_jobs", tenant_id)
    verification_count = await _count("recovery_verifications", tenant_id)

    latest_snapshot = await _latest(
        "recovery_snapshots",
        tenant_id,
        "id,region,snapshot_type,status,completed_at,manifest_sha256,object_count,byte_count,created_at",
    )
    latest_verification = await _latest(
        "recovery_verifications",
        tenant_id,
        "id,snapshot_id,verification_type,passed,checked_count,failure_count,verifier_version,created_at",
    )
    latest_restore = await _latest(
        "recovery_restore_jobs",
        tenant_id,
        "id,snapshot_id,status,clean_host_required,restored_object_count,restored_byte_count,error_code,requested_at,completed_at",
    )

    ready = (
        policy_count > 0
        and snapshot_count > 0
        and object_count > 0
        and verification_count > 0
        and bool(latest_verification and latest_verification.get("passed"))
    )
    status = "ready" if ready else "not_ready"

    return {
        "status": status,
        "generated_at": datetime.now(UTC).isoformat(),
        "policies": policy_count,
        "snapshots": snapshot_count,
        "objects": object_count,
        "restore_jobs": restore_job_count,
        "verifications": verification_count,
        "latest_snapshot": latest_snapshot,
        "latest_verification": latest_verification,
        "latest_restore": latest_restore,
        "external_worm_storage": "configured_by_policy" if policy_count else "not_configured",
        "operational_data_present": bool(snapshot_count or object_count or restore_job_count),
    }


@router.get("/recovery/storage")
async def recovery_storage_status(principal: DeveloperPrincipal = Depends(_principal)) -> dict:
    try:
        return await recovery_storage.verify_access()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Recovery object storage is unavailable") from exc


@router.post("/recovery/snapshots")
async def create_recovery_snapshot(principal: DeveloperPrincipal = Depends(authenticate_request)) -> dict:
    principal.require(("console:write",))
    policy = await _latest(
        "recovery_vault_policies",
        principal.tenant_id,
        "region,enabled",
    )
    if not policy or not policy.get("enabled"):
        raise HTTPException(status_code=409, detail="Recovery vault policy is not enabled")
    try:
        return await create_full_snapshot(principal.tenant_id, str(policy["region"]))
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Recovery snapshot failed") from exc
