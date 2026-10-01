from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from cyclothone.fusion.haversine import haversine_km, max_travel_km
from cyclothone.storage.supabase_client import supabase


@dataclass(frozen=True)
class FusionEvent:
    tenant_id: str
    kind: str
    entity_kind: str
    entity_id: str
    ts: datetime
    site_id: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    device_id: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)


class FusionCorrelator:
    """Deterministic physical/cyber correlation with durable DB state."""

    TRAVEL_WINDOW_SEC = 3600
    DUAL_PRESENCE_WINDOW_SEC = 300
    CAMERA_WINDOW_SEC = 120
    TAILGATE_WINDOW_SEC = 10

    async def process(self, ev: FusionEvent) -> list[dict[str, Any]]:
        if ev.ts.tzinfo is None:
            raise ValueError("event timestamp must be timezone-aware")
        if not ev.tenant_id or not ev.entity_id or not ev.payload.__class__ is dict:
            raise ValueError("invalid fusion event")
        await self._append_edge(ev)
        out: list[dict[str, Any]] = []
        if ev.latitude is not None and ev.longitude is not None:
            found = await self._check_travel(ev)
            if found: out.append(found)
        if ev.kind == "access":
            found = await self._check_revoked_badge(ev)
            if found: out.append(found)
            found = await self._check_tailgate(ev)
            if found: out.append(found)
        elif ev.kind == "camera":
            found = await self._check_camera_conflict(ev)
            if found: out.append(found)
        elif ev.kind == "login":
            found = await self._check_shadow_access(ev)
            if found: out.append(found)
        return out

    async def _append_edge(self, ev: FusionEvent) -> None:
        mapping = {
            "access": ("door", ev.payload.get("door_id"), "entered"),
            "camera": ("camera", ev.payload.get("camera_id"), "observed_by"),
            "login": ("session", ev.payload.get("session_id"), "authenticated"),
            "iot": ("ot_device", ev.payload.get("device_id"), "operated"),
        }
        dst = mapping.get(ev.kind)
        if not dst or not dst[1]:
            return
        await supabase.rpc("fusion_upsert_edge", {
            "p_tenant": ev.tenant_id, "p_src_kind": ev.entity_kind, "p_src_id": ev.entity_id,
            "p_dst_kind": dst[0], "p_dst_id": str(dst[1]), "p_relation": dst[2],
            "p_site": ev.site_id, "p_confidence": 0.9, "p_metadata": ev.payload,
            "p_ts": ev.ts.isoformat(),
        })

    async def _recent_edges(self, ev: FusionEvent, seconds: int) -> list[dict[str, Any]]:
        since = (ev.ts.timestamp() - seconds)
        from datetime import timedelta
        since_iso = (ev.ts - timedelta(seconds=seconds)).isoformat()
        client = await supabase._ensure()
        resp = await client.table("fusion_edges").select("metadata,ts,site_id").eq(
            "tenant_id", ev.tenant_id).eq("src_kind", ev.entity_kind).eq("src_id", ev.entity_id).gte(
            "ts", since_iso).order("ts", desc=True).limit(10).execute()
        return list(resp.data or [])

    async def _check_travel(self, ev: FusionEvent) -> dict[str, Any] | None:
        for row in await self._recent_edges(ev, self.TRAVEL_WINDOW_SEC):
            meta = row.get("metadata") or {}
            lat, lon = meta.get("latitude"), meta.get("longitude")
            if lat is None or lon is None:
                continue
            prev_ts = datetime.fromisoformat(str(row["ts"]).replace("Z", "+00:00"))
            elapsed = int((ev.ts - prev_ts).total_seconds())
            if elapsed <= 0:
                continue
            distance = haversine_km(float(lat), float(lon), float(ev.latitude), float(ev.longitude))
            if distance >= 30 and distance > max_travel_km(elapsed):
                return await self._open(ev, "impossible_travel", "critical", [{
                    "from": {"site": row.get("site_id"), "ts": row["ts"]},
                    "to": {"site": ev.site_id, "ts": ev.ts.isoformat()},
                    "distance_km": round(distance, 2), "elapsed_seconds": elapsed,
                }], distance, elapsed)
            if row.get("site_id") and ev.site_id and row["site_id"] != ev.site_id and elapsed <= self.DUAL_PRESENCE_WINDOW_SEC:
                return await self._open(ev, "dual_presence", "high", [{"sites": [row["site_id"], ev.site_id], "elapsed_seconds": elapsed}], distance, elapsed)
        return None

    async def _check_revoked_badge(self, ev: FusionEvent) -> dict[str, Any] | None:
        badge_id = ev.payload.get("badge_id")
        if not badge_id: return None
        row = await supabase.select_one("badge_holders", "active,valid_until", tenant_id=ev.tenant_id, badge_id=badge_id)
        if not row: return None
        valid = not row.get("valid_until") or datetime.fromisoformat(str(row["valid_until"]).replace("Z", "+00:00")) > ev.ts
        if not bool(row.get("active", True)) or not valid:
            return await self._open(ev, "badge_revoked_use", "critical", [{"badge_id": badge_id, "active": bool(row.get("active", True)), "valid": valid}])
        return None

    async def _check_tailgate(self, ev: FusionEvent) -> dict[str, Any] | None:
        door = ev.payload.get("door_id")
        badge = ev.payload.get("badge_id")
        if not door or not badge: return None
        from datetime import timedelta
        client = await supabase._ensure()
        resp = await client.table("access_events").select("badge_id,user_id,ts").eq("tenant_id", ev.tenant_id).eq(
            "door_id", door).eq("result", "granted").gte("ts", (ev.ts - timedelta(seconds=self.TAILGATE_WINDOW_SEC)).isoformat()).limit(10).execute()
        others = [r for r in (resp.data or []) if r.get("badge_id") and r.get("badge_id") != badge]
        if others:
            return await self._open(ev, "tailgating", "high", [{"door_id": door, "co_entries": len(others)}])
        return None

    async def _check_camera_conflict(self, ev: FusionEvent) -> dict[str, Any] | None:
        if not ev.site_id: return None
        from datetime import timedelta
        client = await supabase._ensure()
        resp = await client.table("access_events").select("id").eq("tenant_id", ev.tenant_id).eq("site_id", ev.site_id).eq(
            "result", "granted").gte("ts", (ev.ts - timedelta(seconds=self.CAMERA_WINDOW_SEC)).isoformat()).limit(1).execute()
        if not resp.data:
            return await self._open(ev, "camera_conflict", "high", [{"camera_id": ev.payload.get("camera_id"), "site_id": ev.site_id}])
        return None

    async def _check_shadow_access(self, ev: FusionEvent) -> dict[str, Any] | None:
        if not ev.site_id or not ev.payload.get("requires_physical_presence"): return None
        from datetime import timedelta
        start = ev.ts.replace(hour=0, minute=0, second=0, microsecond=0)
        client = await supabase._ensure()
        resp = await client.table("access_events").select("id").eq("tenant_id", ev.tenant_id).eq("user_id", ev.entity_id).eq(
            "site_id", ev.site_id).gte("ts", start.isoformat()).limit(1).execute()
        if not resp.data:
            return await self._open(ev, "shadow_access", "high", [{"site_id": ev.site_id, "action": ev.payload.get("action")}])
        return None

    async def _open(self, ev: FusionEvent, kind: str, severity: str, evidence: list[dict[str, Any]], distance_km: float | None = None, elapsed_seconds: int | None = None) -> dict[str, Any]:
        corr_id = await supabase.rpc("fusion_open_correlation", {
            "p_tenant": ev.tenant_id, "p_kind": kind, "p_severity": severity,
            "p_entity_kind": ev.entity_kind, "p_entity_id": ev.entity_id,
            "p_evidence": evidence, "p_distance_km": distance_km,
            "p_elapsed_seconds": elapsed_seconds, "p_seen_at": ev.ts.isoformat(),
        })
        return {"correlation_id": corr_id, "kind": kind, "severity": severity}
