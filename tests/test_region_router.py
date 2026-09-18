from __future__ import annotations

from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException

from cyclothone.routing.region_router import RegionCache, current_region_code, enforce_device_region
from cyclothone.security.device_auth import DeviceIdentity


@pytest.mark.asyncio
async def test_region_cache_loads_active_regions():
    cache = RegionCache()
    response = AsyncMock()
    response.data = [
        {
            "code": "ae-1",
            "name": "UAE Dubai",
            "api_base_url": "https://api.ae-1.cyclothone.security",
            "sandbox_base_url": "https://sandbox.ae-1.cyclothone.security",
            "sovereignty_tier": "sovereign",
            "compliance": {"uae_pdpl": True},
        }
    ]
    with patch("cyclothone.routing.region_router.supabase._retry", new=AsyncMock(return_value=response)):
        await cache.load(force=True)

    assert cache.get("ae-1") is not None
    assert cache.get("ae-1").sovereignty_tier == "sovereign"


def test_current_region_requires_explicit_deployment_identity(monkeypatch):
    monkeypatch.delenv("SENTINEL_REGION", raising=False)
    with pytest.raises(RuntimeError, match="SENTINEL_REGION"):
        current_region_code()

    monkeypatch.setenv("SENTINEL_REGION", "sg-1")
    assert current_region_code() == "sg-1"


@pytest.mark.asyncio
async def test_matching_region_is_allowed(monkeypatch):
    monkeypatch.setenv("SENTINEL_REGION", "ae-1")
    device = DeviceIdentity(str(uuid4()), str(uuid4()), "cert")

    with (
        patch("cyclothone.routing.region_router.region_cache.load", new=AsyncMock()),
        patch("cyclothone.routing.region_router.region_cache.get", return_value=object()),
        patch("cyclothone.routing.region_router.tenant_home_region", new=AsyncMock(return_value="ae-1")),
    ):
        assert await enforce_device_region(None, device) == device


@pytest.mark.asyncio
async def test_wrong_region_returns_421_without_proxying_data(monkeypatch):
    monkeypatch.setenv("SENTINEL_REGION", "ae-1")
    device = DeviceIdentity(str(uuid4()), str(uuid4()), "cert")

    target = type("Region", (), {"api_base_url": "https://api.za-1.cyclothone.security"})()
    with (
        patch("cyclothone.routing.region_router.region_cache.load", new=AsyncMock()),
        patch("cyclothone.routing.region_router.region_cache.get", return_value=target),
        patch("cyclothone.routing.region_router.tenant_home_region", new=AsyncMock(return_value="za-1")),
    ):
        with pytest.raises(HTTPException) as exc:
            await enforce_device_region(None, device)

    assert exc.value.status_code == 421
    assert exc.value.detail["tenant_region"] == "za-1"
    assert exc.value.detail["correct_api"] == target.api_base_url
    # The dependency returns routing metadata only; it never forwards the request body.
