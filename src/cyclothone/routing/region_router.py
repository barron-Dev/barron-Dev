from __future__ import annotations

import os
import time
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status

from sentinel.security.device_auth import DeviceIdentity, get_device
from sentinel.storage.supabase_client import supabase


@dataclass(frozen=True, slots=True)
class RegionInfo:
    code: str
    name: str
    api_base_url: str
    sandbox_base_url: str
    sovereignty_tier: str
    compliance: dict


class RegionCache:
    """Small process-local cache of the replicated region registry."""

    TTL_SECONDS = 3600

    def __init__(self) -> None:
        self._by_code: dict[str, RegionInfo] = {}
        self._loaded_at = 0.0

    async def load(self, force: bool = False) -> None:
        now = time.monotonic()
        if self._by_code and not force and now - self._loaded_at < self.TTL_SECONDS:
            return

        async def operation():
            client = await supabase._ensure()
            return await client.table("regions").select(
                "code,name,api_base_url,sandbox_base_url,sovereignty_tier,compliance"
            ).eq("active", True).execute()

        response = await supabase._retry(operation)
        new_map: dict[str, RegionInfo] = {}
        for row in response.data or []:
            new_map[row["code"]] = RegionInfo(
                code=row["code"],
                name=row["name"],
                api_base_url=row["api_base_url"],
                sandbox_base_url=row["sandbox_base_url"],
                sovereignty_tier=row["sovereignty_tier"],
                compliance=row.get("compliance") or {},
            )
        self._by_code = new_map
        self._loaded_at = now

    def get(self, code: str) -> RegionInfo | None:
        return self._by_code.get(code)


region_cache = RegionCache()


def current_region_code() -> str:
    """Deployment identity. Missing configuration is a hard failure."""
    region = os.getenv("SENTINEL_REGION")
    if not region or not region.strip():
        raise RuntimeError("SENTINEL_REGION must be configured for every data-plane deployment")
    return region.strip()


async def tenant_home_region(tenant_id: str) -> str:
    async def operation():
        client = await supabase._ensure()
        return await client.table("tenants").select("home_region").eq("id", tenant_id).limit(1).execute()

    response = await supabase._retry(operation)
    rows = response.data or []
    if not rows or not rows[0].get("home_region"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant has no valid home region")
    return str(rows[0]["home_region"])


async def enforce_device_region(
    request: Request,
    device: DeviceIdentity = Depends(get_device),
) -> DeviceIdentity:
    """Fail closed when an authenticated device reaches a different data plane.

    A 421 response contains routing metadata only. The API never proxies event,
    evidence, detection, or PII payloads to another region.
    """
    del request
    this_region = current_region_code()
    await region_cache.load()
    home_region = await tenant_home_region(device.tenant_id)

    if home_region == this_region:
        return device

    target = region_cache.get(home_region)
    if target is None or not target.api_base_url.startswith("https://"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="tenant home region is unavailable",
        )

    raise HTTPException(
        status_code=status.HTTP_421_MISDIRECTED_REQUEST,
        detail={
            "error": "wrong_region",
            "tenant_region": home_region,
            "this_region": this_region,
            "correct_api": target.api_base_url,
        },
    )
