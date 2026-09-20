from __future__ import annotations

from datetime import datetime, timezone
from fastapi import APIRouter, Depends

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/trust", tags=["trust-infrastructure"])

WORKER_NAME = "trust-reevaluation"
WORKER_STALE_SECONDS = 45


def _read(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("console:read",))
    return principal


def _fresh_running(heartbeat: dict | None, now: datetime) -> bool:
    if not heartbeat or heartbeat.get("status") != "RUNNING":
        return False
    raw = heartbeat.get("last_heartbeat_at")
    if not raw:
        return False
    try:
        last = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        return (now - last).total_seconds() <= WORKER_STALE_SECONDS
    except (TypeError, ValueError):
        return False


@router.get("/worker/health")
async def trust_worker_health(_: DeveloperPrincipal = Depends(_read)):
    now = datetime.now(timezone.utc)
    heartbeat = None
    queue: dict = {}
    db_ok = True
    worker_ok = False
    queue_ok = False

    try:
        heartbeat = await supabase.select_one(
            "trust_worker_heartbeats",
            "worker_name,status,last_heartbeat_at,last_success_at,last_error_at,last_error_code",
            worker_name=WORKER_NAME,
        )
        queue_result = await supabase.rpc("trust_re_evaluation_queue_stats", {})
        queue = queue_result if isinstance(queue_result, dict) else (queue_result[0] if isinstance(queue_result, list) and queue_result else {})
        worker_ok = _fresh_running(heartbeat, now)
        queue_ok = int(queue.get("failed", 0) or 0) == 0
    except Exception:
        db_ok = False

    return {
        "status": "READY" if db_ok and worker_ok and queue_ok else ("NOT_READY" if not db_ok or not worker_ok else "DEGRADED"),
        "checks": {
            "database": db_ok,
            "worker_heartbeat": worker_ok,
            "queue": queue_ok,
        },
        "worker": {
            "status": heartbeat.get("status") if heartbeat else "NOT_SEEN",
            "last_heartbeat_at": heartbeat.get("last_heartbeat_at") if heartbeat else None,
            "last_success_at": heartbeat.get("last_success_at") if heartbeat else None,
            "last_error_at": heartbeat.get("last_error_at") if heartbeat else None,
            "last_error_code": heartbeat.get("last_error_code") if heartbeat else None,
        },
        "queue": queue,
        "checked_at": now.isoformat(),
    }


@router.get("/readiness")
async def trust_readiness(_: DeveloperPrincipal = Depends(_read)):
    now = datetime.now(timezone.utc)
    checks = {
        "database": False,
        "worker": False,
        "queue": False,
        "authority": False,
    }
    authority = {"status": "UNKNOWN", "active_key_count": 0}
    queue: dict = {}
    heartbeat = None

    try:
        heartbeat = await supabase.select_one(
            "trust_worker_heartbeats",
            "worker_name,status,last_heartbeat_at,last_success_at",
            worker_name=WORKER_NAME,
        )
        queue_result = await supabase.rpc("trust_re_evaluation_queue_stats", {})
        queue = queue_result if isinstance(queue_result, dict) else (queue_result[0] if isinstance(queue_result, list) and queue_result else {})
        keys = await supabase.select(
            "trust_public_key_directory",
            "key_id,status,valid_from,valid_until",
            purpose="TRUST_CERTIFICATE",
            status="ACTIVE",
        )
        checks["database"] = True
        checks["worker"] = _fresh_running(heartbeat, now)
        checks["queue"] = int(queue.get("failed", 0) or 0) == 0
        authority["active_key_count"] = len(keys)
        authority["status"] = "AVAILABLE" if keys else "NOT_CONFIGURED"
        # The trust registry remains operational without a certificate authority key.
        checks["authority"] = True
    except Exception:
        authority["status"] = "UNAVAILABLE"

    overall = "READY" if all(checks.values()) else "NOT_READY"
    return {
        "status": overall,
        "checks": checks,
        "authority": authority,
        "worker": {
            "status": heartbeat.get("status") if heartbeat else "NOT_SEEN",
            "last_heartbeat_at": heartbeat.get("last_heartbeat_at") if heartbeat else None,
        },
        "queue": queue,
        "checked_at": now.isoformat(),
    }
