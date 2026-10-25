from __future__ import annotations

from types import SimpleNamespace

import pytest

from cyclothone.darkweb.native_onion import NativeOnionCrawler
from cyclothone.darkweb.scheduler import DarkWebScheduler


class _Query:
    def __init__(self, rows):
        self.rows = rows

    def select(self, *_args, **_kwargs):
        return self

    def eq(self, *_args, **_kwargs):
        return self

    def limit(self, *_args, **_kwargs):
        return self

    async def execute(self):
        return SimpleNamespace(data=self.rows)


class _Client:
    def __init__(self, rows):
        self.rows = rows

    def table(self, name):
        assert name == "dw_onion_seeds"
        return _Query(self.rows)


@pytest.mark.asyncio
async def test_onion_probe_is_recorded_as_unverified_not_activated(monkeypatch):
    url = f"http://{'a' * 56}.onion/"
    crawler = NativeOnionCrawler(seeds=[url])
    crawler.seed_status[url] = "checked"
    crawler.seed_transport_reached.add(url)
    crawler.seed_http_status[url] = 200
    crawler.seed_content_type[url] = "text/html"
    crawler.seed_response_bytes[url] = 128
    crawler.seed_content_hash[url] = "b" * 64

    client = _Client([{"id": "00000000-0000-0000-0000-000000000001", "seed_type": "candidate_onion_service"}])
    rpc_calls = []

    async def ensure():
        return client

    async def retry(fn, attempts=1):
        return await fn()

    async def rpc(name, params):
        rpc_calls.append((name, params))
        return 1

    monkeypatch.setattr("cyclothone.darkweb.scheduler.supabase._ensure", ensure)
    monkeypatch.setattr("cyclothone.darkweb.scheduler.supabase._retry", retry)
    monkeypatch.setattr("cyclothone.darkweb.scheduler.supabase.rpc", rpc)

    await DarkWebScheduler()._persist_onion_seed_state(crawler)

    assert len(rpc_calls) == 1
    name, params = rpc_calls[0]
    assert name == "dw_record_onion_probe_result"
    assert params["p_outcome"] == "reachable_unverified"
    assert params["p_tor_route_verified"] is False
    assert params["p_publisher_proof_verified"] is False
    assert params["p_independent_corroboration_verified"] is False
    assert params["p_response_sha256"] == "b" * 64
