from __future__ import annotations

from datetime import datetime, timezone
from fastapi import APIRouter, Depends

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/trust", tags=["trust-infrastructure"])


def _read(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("console:read",))
    return principal


@router.get("/worker/health")
async def trust_worker_health(_: DeveloperPrincipal = Depends(_read)):
    now = datetime.now(timezone.utc)
    heartbeat = await supabase.select_one(
        "trust_worker_heartbeats",
        filters={"worker_name": "trust-reevaluation"},
    )
    queue = await supabase.rpc("trust_re_evaluation_queue_stats")

    if not heartbeat:
        return {
            "status": "NOT_READY",
            "worker": {"status": "UNKNOWN", "last_heartbeat_at": None},
            "queue": queue or {},
            "checks": {"worker_heartbeat": False, "queue": True},
            "checked_at": now.isoformat(),
        }

    last = heartbeat.get("last_heartbeat_at")
    last_dt = datetime.fromisoformat(str(last).replace("Z", "+00:00")) if last else None
    alive = bool(last_dt and (now - last_dt).total_seconds() <= 45 and heartbeat.get("status") == "RUNNING")
    queue_ok = int((queue or {}).get("failed", 0) or 0) < 8

    return {
        "status": "READY" if alive and queue_ok else "DEGRADED",
        "worker": {
            "status": heartbeat.get("status"),
            "last_heartbeat_at": last,
            "last_success_at": heartbeat.get("last_success_at"),
            "last_error_at": heartbeat.get("last_error_at"),
            "last_error_code": heartbeat.get("last_error_code"),
        },
        "queue": queue or {},
        "checks": {"worker_heartbeat": alive, "queue": queue_ok},
        "checked_at": now.isoformat(),
    }
