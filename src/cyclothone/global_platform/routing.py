from __future__ import annotations

import time
from dataclasses import dataclass
from uuid import UUID
from cyclothone.storage.supabase_client import supabase

@dataclass(frozen=True)
class RegionInfo:
    code: str
    name: str
    api_base_url: str
    sovereignty_tier: str
    compliance: dict

class RegionCache:
    TTL_SECONDS = 3600
    def __init__(self) -> None:
        self._by_code: dict[str, RegionInfo] = {}
        self._loaded_at = 0.0
    async def load(self, force: bool = False) -> None:
        now = time.time()
        if not force and self._by_code and now - self._loaded_at < self.TTL_SECONDS:
            return
        async def op():
            c = await supabase._ensure()
            return await c.table("regions").select("code,name,api_base_url,sovereignty_tier,compliance").eq("active", True).execute()
        resp = await supabase._retry(op)
        self._by_code = {r["code"]: RegionInfo(r["code"], r["name"], r["api_base_url"], r["sovereignty_tier"], r.get("compliance") or {}) for r in (resp.data or [])}
        self._loaded_at = now
    def get(self, code: str) -> RegionInfo | None:
        return self._by_code.get(code)
    def all_codes(self) -> list[str]:
        return list(self._by_code)

class TenantRouter:
    TTL_SECONDS = 300
    def __init__(self) -> None:
        self._cache: dict[str, tuple[str, float]] = {}
    async def resolve(self, tenant_id: UUID) -> str:
        key, now = str(tenant_id), time.time()
        hit = self._cache.get(key)
        if hit and now - hit[1] < self.TTL_SECONDS:
            return hit[0]
        async def op():
            c = await supabase._ensure()
            return await c.table("tenants").select("home_region").eq("id", key).limit(1).execute()
        rows = (await supabase._retry(op)).data or []
        if not rows or not rows[0].get("home_region"):
            raise RuntimeError(f"tenant {key} has no configured home region")
        region = rows[0]["home_region"]
        self._cache[key] = (region, now)
        return region
    def invalidate(self, tenant_id: UUID) -> None:
        self._cache.pop(str(tenant_id), None)

class GlobalRouter:
    def __init__(self) -> None:
        self.region_cache = RegionCache()
        self.tenant_router = TenantRouter()
    async def resolve_target(self, tenant_id: UUID) -> RegionInfo:
        await self.region_cache.load()
        region = self.region_cache.get(await self.tenant_router.resolve(tenant_id))
        if region is None:
            raise RuntimeError("tenant home region is not active")
        return region
