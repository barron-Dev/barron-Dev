from __future__ import annotations

import pytest

from cyclothone.darkweb.native_onion import _safe_onion_url
from cyclothone.darkweb.scheduler import DarkWebScheduler


def test_native_onion_requires_v3_hostname():
    assert _safe_onion_url(f"http://{'a' * 56}.onion/") is not None
    assert _safe_onion_url("http://shortname.onion/") is None
    assert _safe_onion_url(f"http://{'a' * 55}.onion/") is None
    assert _safe_onion_url(f"http://{'a' * 56}x.onion/") is None


@pytest.mark.asyncio
async def test_native_onion_seed_registry_is_closed_when_feature_gate_off(monkeypatch):
    monkeypatch.setenv("CYCLOTHONE_DW_NATIVE_ONION_ENABLED", "false")
    monkeypatch.setenv("CYCLOTHONE_DW_ONION_SEEDS", f"http://{'a' * 56}.onion/")
    seeds, origins, discovered = await DarkWebScheduler()._onion_seed_urls()
    assert seeds == []
    assert origins == {}
    assert discovered == {}
