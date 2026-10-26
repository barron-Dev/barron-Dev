from __future__ import annotations

import pytest

from cyclothone.brand import typosquat


@pytest.mark.asyncio
async def test_dns_candidate_is_not_reported_as_verified_threat(monkeypatch):
    monkeypatch.setattr(
        typosquat,
        "generate_permutations",
        lambda _domain, _limit: [("example-lookalike.test", "insertion")],
    )
    monkeypatch.setattr(typosquat, "_resolves", _async_true)

    captured = {}

    async def record(*args):
        captured.update(args[-1])
        return True

    monkeypatch.setattr(typosquat.TyposquatScanner, "_record", staticmethod(record))
    result = await typosquat.TyposquatScanner().scan_brand(
        {"primary_domain": "example.com", "tenant_id": "tenant", "id": "brand"}
    )

    assert result["recorded_candidates"] == 1
    assert result["threats"] == 1
    assert result["verified_threats"] == 0
    assert result["candidate_only"] is True
    assert captured["evidence_stage"] == "dns_resolution_only"
    assert captured["verification_status"] == "unverified_candidate"
    assert captured["http_content_inspected"] is False
    assert captured["tls_identity_verified"] is False


@pytest.mark.asyncio
async def test_failed_persistence_is_not_counted_as_a_saved_candidate(monkeypatch):
    monkeypatch.setattr(
        typosquat,
        "generate_permutations",
        lambda _domain, _limit: [("example-lookalike.test", "insertion")],
    )
    monkeypatch.setattr(typosquat, "_resolves", _async_true)

    async def record(*_args):
        return False

    monkeypatch.setattr(typosquat.TyposquatScanner, "_record", staticmethod(record))
    result = await typosquat.TyposquatScanner().scan_brand(
        {"primary_domain": "example.com", "tenant_id": "tenant", "id": "brand"}
    )

    assert result["recorded_candidates"] == 0
    assert result["threats"] == 0
    assert result["persistence_failures"] == 1


async def _async_true(_domain):
    return True
