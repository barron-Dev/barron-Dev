from __future__ import annotations

from uuid import uuid4

import pytest

from sentinel.deception.engine import DeceptionEngine
from sentinel.deception.models import ArtifactSpec


@pytest.mark.asyncio
async def test_create_stores_only_token_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    tenant_id = uuid4()
    captured: dict = {}

    async def insert_one(table: str, values: dict):
        captured.update(values)
        return {"id": str(uuid4())}

    monkeypatch.setattr("sentinel.deception.engine.supabase.insert_one", insert_one)
    artifact = await DeceptionEngine(callback_base_url="https://sentinel.example").create(
        ArtifactSpec(tenant_id=tenant_id, artifact_type="fake_aws_key", name="finance-canary", target="finance-share")
    )

    assert artifact.secret.startswith("AKIA")
    assert captured["token_hash"] != artifact.secret
    assert len(captured["token_hash"]) == 64
    assert captured["metadata"]["inert"] is True
    assert artifact.callback_url.startswith("https://sentinel.example/api/v1/deception/callback/sdc_")


@pytest.mark.asyncio
async def test_callback_uses_hashed_token_and_returns_trigger(monkeypatch: pytest.MonkeyPatch) -> None:
    tenant_id = uuid4()
    artifact_id = uuid4()
    trigger_id = uuid4()
    calls: dict = {}

    async def rpc(function: str, params: dict):
        calls["function"] = function
        calls["params"] = params
        return [{
            "trigger_id": str(trigger_id),
            "tenant_id": str(tenant_id),
            "artifact_id": str(artifact_id),
            "severity": "critical",
            "artifact_type": "honeyfile",
        }]

    monkeypatch.setattr("sentinel.deception.engine.supabase.rpc", rpc)
    result = await DeceptionEngine(callback_base_url="https://sentinel.example").record_callback(
        "sdc_opaque-token", source_ip="203.0.113.10", user_agent="test-client"
    )

    assert result is not None
    assert result.trigger_id == trigger_id
    assert result.tenant_id == tenant_id
    assert calls["function"] == "deception_record_trigger"
    assert calls["params"]["p_token_hash"] != "sdc_opaque-token"
    assert len(calls["params"]["p_token_hash"]) == 64
