from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response

from cyclothone.security.device_auth import DeviceIdentity, get_device
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/agent/model", tags=["agent-model"])


async def _active_model(tenant_id: str) -> dict[str, Any]:
    async def lookup():
        client = await supabase._ensure()
        tenant_query = (
            client.table("models")
            .select("id,version,algorithm,artifact_path,artifact_sha256,feature_names,metrics")
            .eq("tenant_id", tenant_id)
            .eq("active", True)
            .limit(1)
        )
        response = await tenant_query.execute()
        rows = response.data or []
        if rows:
            return rows[0]
        response = await (
            client.table("models")
            .select("id,version,algorithm,artifact_path,artifact_sha256,feature_names,metrics")
            .is_("tenant_id", "null")
            .eq("active", True)
            .limit(1)
            .execute()
        )
        rows = response.data or []
        return rows[0] if rows else None

    model = await supabase._retry(lookup, attempts=2)
    if not model:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no active model for device tenant")
    return model


@router.get("")
async def active_model(device: DeviceIdentity = Depends(get_device)) -> dict[str, Any]:
    model = await _active_model(device.tenant_id)
    return {
        "model_id": model["id"],
        "version": model["version"],
        "algorithm": model["algorithm"],
        "artifact_sha256": model["artifact_sha256"],
        "feature_names": model["feature_names"],
        "metrics": model.get("metrics") or {},
    }


@router.get("/artifact")
async def download_model(device: DeviceIdentity = Depends(get_device)) -> Response:
    model = await _active_model(device.tenant_id)

    async def download():
        client = await supabase._ensure()
        return await client.storage.from_("models").download(model["artifact_path"])

    artifact = await supabase._retry(download, attempts=3)

    async def record_sync():
        client = await supabase._ensure()
        return await (
            client.table("agent_model_sync")
            .upsert(
                {
                    "device_id": device.device_id,
                    "model_version": model["version"],
                    "model_id": model["id"],
                    "artifact_sha256": model["artifact_sha256"],
                },
                on_conflict="device_id,model_version",
            )
            .execute()
        )

    await supabase._retry(record_sync, attempts=2)
    return Response(
        content=artifact,
        media_type="application/octet-stream",
        headers={
            "X-cyclothone-Model-Version": str(model["version"]),
            "X-cyclothone-Artifact-SHA256": model["artifact_sha256"],
        },
    )
