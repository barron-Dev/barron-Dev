from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase
from cyclothone.watchtower.ingest import (
    CameraConfigurationError,
    CameraStreamError,
    RTSPCameraConfig,
    stream_rtsp_frames,
)

router = APIRouter(prefix="/watchtower", tags=["ai-security-watchtower"])


def _allowed_hosts() -> frozenset[str]:
    values = os.getenv("WATCHTOWER_CAMERA_ALLOWED_HOSTS", "")
    return frozenset(host.strip().rstrip(".").lower() for host in values.split(",") if host.strip())


def _read(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("watchtower:read",))
    return principal


def _manage(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("watchtower:manage",))
    return principal


class CameraCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    endpoint: str = Field(min_length=1, max_length=2048)
    site_id: UUID | None = None


_CAMERA_COLUMNS = "id,tenant_id,site_id,name,endpoint,endpoint_host,protocol,enabled,created_by,created_at,updated_at"


def _validated_endpoint(endpoint: str) -> tuple[str, str]:
    parsed = urlsplit(endpoint)
    if parsed.scheme not in {"rtsp", "rtsps"} or not parsed.hostname:
        raise HTTPException(422, "endpoint_must_use_rtsp_or_rtsps")
    if parsed.username is not None or parsed.password is not None:
        raise HTTPException(422, "embedded_camera_credentials_forbidden")
    if parsed.query or parsed.fragment:
        raise HTTPException(422, "endpoint_query_and_fragment_forbidden")
    try:
        parsed.port
    except ValueError as exc:
        raise HTTPException(422, "invalid_endpoint_port") from exc
    host = parsed.hostname.rstrip(".").lower()
    if host not in _allowed_hosts():
        raise HTTPException(422, "camera_host_not_allowlisted_by_server")
    return host, parsed.scheme


@router.post("/cameras", status_code=201)
async def register_camera(body: CameraCreate, principal: DeveloperPrincipal = Depends(_manage)):
    host, protocol = _validated_endpoint(body.endpoint)
    if body.site_id:
        async def _site():
            client = await supabase._ensure()
            return await client.table("physical_sites").select("id").eq(
                "id", str(body.site_id)
            ).eq("tenant_id", principal.tenant_id).limit(1).execute()
        if not (await supabase._retry(_site)).data:
            raise HTTPException(404, "site_not_found")
    row = {
        "tenant_id": principal.tenant_id,
        "site_id": str(body.site_id) if body.site_id else None,
        "name": body.name.strip(),
        "endpoint": body.endpoint,
        "endpoint_host": host,
        "protocol": protocol,
        "created_by": principal.user_id or principal.app_id,
    }
    async def _insert():
        client = await supabase._ensure()
        return await client.table("watchtower_cameras").insert(row).select(_CAMERA_COLUMNS).single().execute()
    try:
        result = (await supabase._retry(_insert)).data
    except Exception as exc:
        raise HTTPException(503, "camera_registry_unavailable") from exc
    if not result:
        raise HTTPException(503, "camera_registration_not_confirmed")
    return result


@router.get("/cameras")
async def list_cameras(
    limit: int = Query(100, ge=1, le=500),
    principal: DeveloperPrincipal = Depends(_read),
):
    async def _list():
        client = await supabase._ensure()
        return await client.table("watchtower_cameras").select(_CAMERA_COLUMNS).eq(
            "tenant_id", principal.tenant_id
        ).order("created_at", desc=True).limit(limit).execute()
    try:
        return list((await supabase._retry(_list)).data or [])
    except Exception as exc:
        raise HTTPException(503, "camera_registry_unavailable") from exc


@router.post("/cameras/{camera_id}/probe", status_code=201)
async def probe_camera(camera_id: UUID, principal: DeveloperPrincipal = Depends(_manage)):
    async def _load():
        client = await supabase._ensure()
        return await client.table("watchtower_cameras").select(_CAMERA_COLUMNS).eq(
            "id", str(camera_id)
        ).eq("tenant_id", principal.tenant_id).eq("enabled", True).limit(1).execute()
    try:
        rows = (await supabase._retry(_load)).data or []
    except Exception as exc:
        raise HTTPException(503, "camera_registry_unavailable") from exc
    if not rows:
        raise HTTPException(404, "enabled_camera_not_found")
    camera = rows[0]
    # Revalidate at execution time; configuration may have been changed out of band.
    host, protocol = _validated_endpoint(camera["endpoint"])
    if host != camera["endpoint_host"] or protocol != camera["protocol"]:
        raise HTTPException(409, "camera_endpoint_registry_mismatch")
    allowed = _allowed_hosts()
    config = RTSPCameraConfig(
        tenant_id=principal.tenant_id,
        camera_id=str(camera_id),
        endpoint=camera["endpoint"],
        allowed_hosts=allowed,
    )
    started = time.monotonic()
    outcome = "failed"
    frame_sha256 = None
    frame_sequence = None
    error_code = None
    try:
        stream = stream_rtsp_frames(config)
        try:
            frame = await anext(stream)
            frame_sha256 = frame.sha256
            frame_sequence = frame.sequence
            outcome = "connected"
        finally:
            await stream.aclose()
    except CameraConfigurationError as exc:
        raise HTTPException(422, str(exc)) from exc
    except CameraStreamError as exc:
        error_code = str(exc)[:120]
        outcome = "unavailable" if error_code == "ffmpeg_executable_not_installed" else "failed"
    except Exception:
        # Do not return raw transport errors, endpoints, or credentials to callers.
        error_code = "camera_probe_internal_error"
        outcome = "failed"
    duration_ms = max(0, int((time.monotonic() - started) * 1000))
    row = {
        "tenant_id": principal.tenant_id,
        "camera_id": str(camera_id),
        "outcome": outcome,
        "frame_sha256": frame_sha256,
        "frame_sequence": frame_sequence,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": duration_ms,
        "error_code": error_code,
    }
    async def _persist():
        client = await supabase._ensure()
        return await client.table("watchtower_camera_probes").insert(row).select(
            "id,tenant_id,camera_id,outcome,frame_sha256,frame_sequence,observed_at,duration_ms,error_code"
        ).single().execute()
    try:
        result = (await supabase._retry(_persist)).data
    except Exception as exc:
        raise HTTPException(503, "probe_evidence_persistence_failed") from exc
    if not result:
        raise HTTPException(503, "probe_evidence_persistence_unconfirmed")
    return result


@router.get("/cameras/{camera_id}/probes")
async def list_camera_probes(
    camera_id: UUID,
    limit: int = Query(50, ge=1, le=200),
    principal: DeveloperPrincipal = Depends(_read),
):
    async def _list():
        client = await supabase._ensure()
        return await client.table("watchtower_camera_probes").select(
            "id,tenant_id,camera_id,outcome,frame_sha256,frame_sequence,observed_at,duration_ms,error_code"
        ).eq("tenant_id", principal.tenant_id).eq("camera_id", str(camera_id)).order(
            "observed_at", desc=True
        ).limit(limit).execute()
    try:
        return list((await supabase._retry(_list)).data or [])
    except Exception as exc:
        raise HTTPException(503, "probe_evidence_unavailable") from exc
