from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from sentinel.ml.detector import server_detector
from sentinel.models.events import EndpointEvent
from sentinel.security.device_auth import DeviceIdentity, get_device
from sentinel.storage.supabase_client import supabase

router = APIRouter(prefix="/agent/events", tags=["agent-events"])


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def ingest_event(
    event: EndpointEvent,
    device: DeviceIdentity = Depends(get_device),
):
    detection = await server_detector.detect(tenant_id=device.tenant_id, event=event)

    async def persist():
        client = await supabase._ensure()
        return await (
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

    try:
        await supabase._retry(persist, attempts=2)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="event persistence unavailable",
        ) from exc

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
    }
