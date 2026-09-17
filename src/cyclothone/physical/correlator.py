from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sentinel.storage.supabase_client import supabase

logger = logging.getLogger(__name__)
AFTER_HOURS_START = 20
AFTER_HOURS_END = 6


class PhysicalCorrelator:
    """Tenant-scoped correlation of physical events with digital audit events."""

    async def run_window(self, tenant_id: UUID, window_minutes: int = 15) -> dict:
        if not 1 <= window_minutes <= 120:
            raise ValueError("window_minutes must be between 1 and 120")
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        created = 0
        created += await self._badge_remote(tenant_id, since)
        created += await self._after_hours(tenant_id, since)
        created += await self._camera_no_badge(tenant_id, since)
        created += await self._revoked(tenant_id, since)
        return {"created": created}

    async def _rows(self, table: str, tenant_id: UUID, since: datetime, limit: int = 200, **filters) -> list[dict]:
        async def _do():
            client = await supabase._ensure()
            q = client.table(table).select("*").eq("tenant_id", str(tenant_id)).gte("ts", since.isoformat()).order("ts", desc=True).limit(limit)
            for key, value in filters.items():
                q = q.eq(key, value)
            return await q.execute()
        try:
            return list((await supabase._retry(_do)).data or [])
        except Exception as exc:
            logger.debug("physical query failed: %s", exc)
            return []

    async def _badge_remote(self, tenant_id: UUID, since: datetime) -> int:
        grants = await self._rows("access_events", tenant_id, since, result="granted")
        count = 0
        for row in grants:
            uid, ts = row.get("user_id"), self._parse_ts(row.get("ts"))
            if not uid or not ts or await self._login_near(uid, ts):
                continue
            if not await self._recent_login(uid):
                continue
            if await self._duplicate(tenant_id, "badge_and_remote_login", row["id"], "access_event_id"):
                continue
            await self._create(tenant_id, row.get("site_id"), uid, "badge_and_remote_login", "high", "Badge used while user was active remotely", {"access_event_id": row["id"], "ts": row["ts"]})
            count += 1
        return count

    async def _after_hours(self, tenant_id: UUID, since: datetime) -> int:
        grants = await self._rows("access_events", tenant_id, since, result="granted")
        count = 0
        for row in grants:
            uid, ts = row.get("user_id"), self._parse_ts(row.get("ts"))
            if not uid or not ts or not self._is_after_hours(ts):
                continue
            if await self._group(uid, "after_hours") or await self._duplicate(tenant_id, "after_hours_access", row["id"], "access_event_id"):
                continue
            await self._create(tenant_id, row.get("site_id"), uid, "after_hours_access", "high", "After-hours badge access", {"access_event_id": row["id"], "ts": row["ts"]})
            count += 1
        return count

    async def _camera_no_badge(self, tenant_id: UUID, since: datetime) -> int:
        cams = await self._rows("camera_events", tenant_id, since, kind="person")
        count = 0
        for row in cams:
            if await self._badge_near(row.get("site_id"), self._parse_ts(row.get("ts"))):
                continue
            if await self._duplicate(tenant_id, "camera_motion_no_badge", row["id"], "camera_event_id"):
                continue
            await self._create(tenant_id, row.get("site_id"), None, "camera_motion_no_badge", "high", "Person detected without matching badge event", {"camera_event_id": row["id"], "ts": row["ts"]})
            count += 1
        return count

    async def _revoked(self, tenant_id: UUID, since: datetime) -> int:
        grants = await self._rows("access_events", tenant_id, since, result="granted")
        count = 0
        for row in grants:
            async def _do():
                client = await supabase._ensure()
                return await client.table("badge_holders").select("active").eq("site_id", row["site_id"]).eq("badge_id", row["badge_id"]).limit(1).execute()
            try:
                data = (await supabase._retry(_do)).data or []
                if not data or data[0].get("active", True) or await self._duplicate(tenant_id, "badge_revoked_use", row["id"], "access_event_id"):
                    continue
                await self._create(tenant_id, row.get("site_id"), row.get("user_id"), "badge_revoked_use", "critical", "Revoked badge used at door", {"access_event_id": row["id"]})
                count += 1
            except Exception as exc:
                logger.debug("revoked badge check failed: %s", exc)
        return count

    async def _login_near(self, uid: str, ts: datetime) -> bool:
        return await self._audit_exists(uid, ts - timedelta(minutes=10), ts + timedelta(minutes=10))

    async def _recent_login(self, uid: str) -> bool:
        now = datetime.now(timezone.utc)
        return await self._audit_exists(uid, now - timedelta(minutes=10), now)

    async def _audit_exists(self, uid: str, lo: datetime, hi: datetime) -> bool:
        async def _do():
            client = await supabase._ensure()
            return await client.table("audit_log").select("id").eq("actor", str(uid)).in_("action", ["login", "session.start"]).gte("ts", lo.isoformat()).lte("ts", hi.isoformat()).limit(1).execute()
        try:
            return bool((await supabase._retry(_do)).data)
        except Exception:
            return False

    async def _group(self, uid: str, group: str) -> bool:
        async def _do():
            client = await supabase._ensure()
            return await client.table("badge_holders").select("access_groups").eq("user_id", str(uid)).limit(1).execute()
        try:
            rows = (await supabase._retry(_do)).data or []
            return bool(rows and group in (rows[0].get("access_groups") or []))
        except Exception:
            return False

    async def _badge_near(self, site_id: str | None, ts: datetime | None) -> bool:
        if not site_id or not ts:
            return True
        async def _do():
            client = await supabase._ensure()
            return await client.table("access_events").select("id").eq("site_id", site_id).eq("result", "granted").gte("ts", (ts - timedelta(minutes=2)).isoformat()).lte("ts", (ts + timedelta(minutes=2)).isoformat()).limit(1).execute()
        try:
            return bool((await supabase._retry(_do)).data)
        except Exception:
            return True

    async def _duplicate(self, tenant_id: UUID, pattern: str, source_id: int, key: str) -> bool:
        async def _do():
            client = await supabase._ensure()
            return await client.table("physical_digital_correlations").select("id").eq("tenant_id", str(tenant_id)).eq("pattern", pattern).contains("evidence", {key: source_id}).limit(1).execute()
        try:
            return bool((await supabase._retry(_do)).data)
        except Exception:
            return False

    async def _create(self, tenant_id: UUID, site_id: str | None, user_id: str | None, pattern: str, severity: str, title: str, evidence: dict) -> None:
        async def _do():
            client = await supabase._ensure()
            return await client.table("physical_digital_correlations").insert({"tenant_id": str(tenant_id), "site_id": site_id, "user_id": user_id, "pattern": pattern, "severity": severity, "title": title[:200], "evidence": evidence}).execute()
        try:
            await supabase._retry(_do, attempts=2)
        except Exception as exc:
            logger.warning("correlation write failed: %s", exc)

    @staticmethod
    def _parse_ts(value: object) -> datetime | None:
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00")) if value else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _is_after_hours(value: datetime) -> bool:
        return value.hour >= AFTER_HOURS_START or value.hour < AFTER_HOURS_END

    @staticmethod
    def _is_uuid(value: str) -> bool:
        try:
            UUID(value)
            return True
        except (TypeError, ValueError, AttributeError):
            return False
