from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any, Awaitable, Callable
from uuid import UUID

from sentinel.storage.supabase_client import supabase

logger = logging.getLogger(__name__)
Check = Callable[[UUID, datetime, datetime], Awaitable[tuple[str, float, dict[str, Any]]]]

async def _count(table: str, tenant_id: UUID, time_field: str | None = None, start: datetime | None = None, end: datetime | None = None) -> int:
    async def _do():
        q = (await supabase._ensure()).table(table).select("id", count="exact").eq("tenant_id", str(tenant_id))
        if time_field and start:
            q = q.gte(time_field, start.isoformat())
        if time_field and end:
            q = q.lt(time_field, end.isoformat())
        return await q.limit(1).execute()
    try:
        response = await supabase._retry(_do, attempts=2)
        return int(response.count or 0)
    except Exception as exc:  # noqa: BLE001
        logger.warning("compliance count failed for %s: %s", table, exc)
        return 0

async def _safe_count(table: str, tenant_id: UUID, time_field: str | None, start: datetime, end: datetime) -> tuple[int, bool]:
    async def _do():
        q = (await supabase._ensure()).table(table).select("id", count="exact").eq("tenant_id", str(tenant_id))
        if time_field:
            q = q.gte(time_field, start.isoformat()).lt(time_field, end.isoformat())
        return await q.limit(1).execute()
    try:
        response = await supabase._retry(_do, attempts=2)
        return int(response.count or 0), True
    except Exception:
        return 0, False

async def check_endpoint_coverage(tenant_id: UUID, start: datetime, end: datetime):
    count, readable = await _safe_count("devices", tenant_id, None, start, end)
    if not readable:
        return "unknown", 0.0, {"source": "devices", "availability": "unavailable"}
    return ("passing", 1.0, {"enrolled_devices": count}) if count else ("failing", 0.0, {"enrolled_devices": 0})

async def check_detection_active(tenant_id: UUID, start: datetime, end: datetime):
    count, readable = await _safe_count("detections", tenant_id, "created_at", start, end)
    if not readable:
        return "unknown", 0.0, {"source": "detections", "availability": "unavailable"}
    return ("passing", 1.0, {"detections_in_period": count, "source": "detections"}) if count else ("partial", 0.5, {"detections_in_period": 0, "note": "No detections observed; this is not proof that monitoring is disabled."})

async def check_ir_process(tenant_id: UUID, start: datetime, end: datetime):
    cases, cases_ok = await _safe_count("crime_cases", tenant_id, "created_at", start, end)
    commands, commands_ok = await _safe_count("commands", tenant_id, "issued_at", start, end)
    if not (cases_ok or commands_ok):
        return "unknown", 0.0, {"availability": "case and command sources unavailable"}
    activity = cases + commands
    return ("passing", 1.0, {"cases_in_period": cases, "commands_in_period": commands}) if activity else ("partial", 0.5, {"cases_in_period": 0, "commands_in_period": 0, "note": "No response activity observed in the selected period."})

async def check_backup_active(tenant_id: UUID, start: datetime, end: datetime):
    del start, end
    async def _do():
        return await (await supabase._ensure()).table("recovery_vault_policies").select("id,enabled").eq("tenant_id", str(tenant_id)).eq("enabled", True).execute()
    try:
        response = await supabase._retry(_do, attempts=2)
        policies = response.data or []
    except Exception:
        return "unknown", 0.0, {"source": "recovery_vault_policies", "availability": "unavailable"}
    return ("passing", 1.0, {"enabled_policies": len(policies)}) if policies else ("failing", 0.0, {"enabled_policies": 0})

async def check_backup_tested(tenant_id: UUID, start: datetime, end: datetime):
    snapshots, snap_ok = await _safe_count("recovery_snapshots", tenant_id, "created_at", start, end)
    restores, restore_ok = await _safe_count("recovery_restore_jobs", tenant_id, "created_at", start, end)
    if not (snap_ok or restore_ok):
        return "unknown", 0.0, {"availability": "recovery sources unavailable"}
    if snapshots and restores:
        return "passing", 1.0, {"snapshots": snapshots, "restore_jobs": restores}
    if snapshots:
        return "partial", 0.6, {"snapshots": snapshots, "restore_jobs": 0, "note": "Snapshots exist but no restore job was observed in the selected period."}
    return "failing", 0.0, {"snapshots": 0, "restore_jobs": restores}

async def check_audit_activity(tenant_id: UUID, start: datetime, end: datetime):
    count, readable = await _safe_count("audit_log", tenant_id, "ts", start, end)
    if not readable:
        return "unknown", 0.0, {"source": "audit_log", "availability": "unavailable"}
    return ("passing", 1.0, {"audit_entries": count}) if count else ("partial", 0.5, {"audit_entries": 0, "note": "No audit entries observed in the selected period."})

async def check_data_trust_active(tenant_id: UUID, start: datetime, end: datetime):
    count, readable = await _safe_count("data_trust_transfer_events", tenant_id, "observed_at", start, end)
    if not readable:
        return "unknown", 0.0, {"source": "data_trust_transfer_events", "availability": "unavailable"}
    return ("passing", 1.0, {"transfer_events": count}) if count else ("partial", 0.5, {"transfer_events": 0, "note": "No transfer telemetry observed; absence of events is not proof that DLP is disabled."})

CHECKS: dict[str, Check] = {
    "endpoint_coverage": check_endpoint_coverage,
    "detection_active": check_detection_active,
    "ir_process": check_ir_process,
    "backup_active": check_backup_active,
    "backup_tested": check_backup_tested,
    "audit_activity": check_audit_activity,
    "data_trust_active": check_data_trust_active,
}
