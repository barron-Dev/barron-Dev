from __future__ import annotations

import os
from datetime import UTC, datetime

from fastapi import APIRouter, Depends

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.routing.region_router import current_region_code, region_cache

router = APIRouter(tags=["control-plane"])


def _principal(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("console:read",))
    return principal


@router.get("/platform/settings")
async def platform_settings(principal: DeveloperPrincipal = Depends(_principal)) -> dict:
    region = current_region_code()
    region_entry = region_cache.get(region)
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "tenant_id": principal.tenant_id,
        "region": region,
        "region_registered": region_entry is not None,
        "residency": "strict",
        "api": {"version": "0.1.0", "health": "runtime"},
        "configuration": {
            "cyclothone_region": bool(os.getenv("CYCLOTHONE_REGION")),
            "supabase_url": bool(os.getenv("SUPABASE_URL")),
            "supabase_service_key": bool(os.getenv("SUPABASE_SERVICE_ROLE_KEY")),
        },
    }


@router.get("/assurance/recovery")
async def recovery_status(principal: DeveloperPrincipal = Depends(_principal)) -> dict:
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "tenant_id": principal.tenant_id,
        "status": "configuration_required",
        "immutable_object_lock_required": True,
        "object_lock_mode": "COMPLIANCE",
        "verification": "SHA-256 before restore",
        "rpo_minutes": 15,
        "note": "Recovery restore is fail-closed until an immutable vault implementation is configured.",
    }


@router.get("/intelligence/scam")
async def scam_status(principal: DeveloperPrincipal = Depends(_principal)) -> dict:
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "tenant_id": principal.tenant_id,
        "status": "ready",
        "detectors": {
            "message": {"available": True, "type": "deterministic_signal_generator"},
            "voice": {"available": True, "type": "acoustic_feature_heuristic"},
        },
        "verdicts": ["safe", "suspicious", "malicious"],
        "note": "Detectors emit signals; final policy decisions remain in the canonical security boundary.",
    }
