from __future__ import annotations

import hashlib
import json
from uuid import NAMESPACE_URL, UUID, uuid5

from fastapi import APIRouter, Depends, HTTPException, status

from cyclothone.automation.auto_case import process_persisted_detection
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
        json.dumps(
            event_payload,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    ).hexdigest()

    async def persist():
        client = await supabase._ensure()
        return await (
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

    try:
        await supabase._retry(persist, attempts=2)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="event persistence unavailable",
        ) from exc

    if detection is not None:
        detection_payload = {
            "id": str(uuid5(NAMESPACE_URL, f"ml:{canonical_id}")),
            "tenant_id": device.tenant_id,
            "device_id": device.device_id,
            "event_id": str(canonical_id),
            "detector": "ml",
            "score": float(detection.score),
            "verdict": "malicious" if detection.score >= 0.5 else "benign",
            "reasons": ["ml_score"],
            "evidence": {
                "model_version": detection.model_version,
                "event_id": event.event_id,
                "event_type": event.kind,
            },
        }

        async def persist_detection():
            client = await supabase._ensure()
            return await (
                client.table("detections")
                .upsert(detection_payload, on_conflict="id")
                .execute()
            )

        try:
            await supabase._retry(persist_detection, attempts=2)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="detection persistence unavailable",
            ) from exc

        try:
            await process_persisted_detection(
                detection_id=UUID(detection_payload["id"]),
                tenant_id=device.tenant_id,
                device_id=device.device_id,
                detector="ml",
                score=float(detection.score),
                verdict=detection_payload["verdict"],
                reasons=detection_payload["reasons"],
                evidence=detection_payload["evidence"],
            )
        except Exception:
            # Detection remains durable; automation can be retried independently.
            pass

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
