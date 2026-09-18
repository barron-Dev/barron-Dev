from __future__ import annotations

import hashlib
import json

from fastapi import APIRouter, Depends, HTTPException, status

from cyclothone.federation.promotion import (
    FederationDetectionPromoter,
    canonical_event_uuid,
    extract_federation_observations,
)
from cyclothone.ml.detector import server_detector
from cyclothone.models.events import EndpointEvent
from cyclothone.security.device_auth import DeviceIdentity, get_device
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/agent/events", tags=["agent-events"])
_federation_promoter = FederationDetectionPromoter()


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def ingest_event(
    event: EndpointEvent,
    device: DeviceIdentity = Depends(get_device),
):
    detection = await server_detector.detect(tenant_id=device.tenant_id, event=event)
    canonical_id = canonical_event_uuid(event.event_id)
    event_payload = dict(event.payload)
    event_payload.update(
        {
            "agent_event_id": event.event_id,
            "schema_version": event.schema_version,
            "host_id": event.host_id,
            "pid": event.pid,
            "parent_pid": event.parent_pid,
            "image": event.image,
            "command_line": event.command_line,
            "remote_address": event.remote_address,
            "remote_port": event.remote_port,
        }
    )
    event_sha = hashlib.sha256(
        json.dumps(event_payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()

    async def persist():
        client = await supabase._ensure()
        endpoint_result = await (
            client.table("endpoint_events")
            .upsert(
                {
                    "tenant_id": device.tenant_id,
                    "device_id": device.device_id,
                    "event_id": event.event_id,
                    "schema_version": event.schema_version,
                    "event_type": event.kind,
                    "observed_at": event.observed_at.isoformat(),
                    "payload": event.payload,
                },
                on_conflict="device_id,event_id",
            )
            .execute()
        )
        canonical_result = await (
            client.table("events")
            .upsert(
                {
                    "id": str(canonical_id),
                    "tenant_id": device.tenant_id,
                    "device_id": device.device_id,
                    "event_type": event.kind,
                    "ts": event.observed_at.isoformat(),
                    "payload": event_payload,
                    "sha256": event_sha,
                },
                on_conflict="id",
            )
            .execute()
        )
        return endpoint_result, canonical_result

    try:
        await supabase._retry(persist, attempts=2)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="event persistence unavailable",
        ) from exc

    federation_detections: list[str] = []
    observations = extract_federation_observations(
        kind=event.kind,
        image=event.image,
        command_line=event.command_line,
        remote_address=event.remote_address,
        payload=event.payload,
    )
    if observations:
        try:
            promoted = await _federation_promoter.evaluate_event(
                tenant_id=device.tenant_id,
                device_id=device.device_id,
                event_id=canonical_id,
                observations=observations,
            )
            federation_detections = [str(item) for item in promoted]
        except Exception:
            federation_detections = []

    return {
        "event_id": event.event_id,
        "device_id": device.device_id,
        "accepted": True,
        "ml": None
        if detection is None
        else {
            "score": detection.score,
            "model_version": detection.model_version,
        },
        "federation_detections": federation_detections,
    }
