from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from sentinel.api.routes.agent_events import router
from sentinel.models.events import EndpointEvent
from sentinel.security.device_auth import DeviceIdentity, get_device


def test_agent_event_contract_matches_rust_shape() -> None:
    event = EndpointEvent.model_validate(
        {
            "schema_version": 1,
            "event_id": "evt-1",
            "observed_at": "2026-09-16T00:00:00Z",
            "kind": "process_start",
            "host_id": "host-1",
            "pid": 42,
            "parent_pid": 4,
            "image": r"C:\Windows\System32\notepad.exe",
            "command_line": "notepad.exe",
            "remote_address": None,
            "remote_port": None,
            "payload": {"child_processes": 2},
        }
    )
    assert event.ml_type() == "process"
    assert event.payload["child_processes"] == 2


def test_mtls_dependency_fails_closed_without_tls() -> None:
    app = FastAPI()

    @app.get("/device")
    async def device(device: DeviceIdentity = Depends(get_device)):
        return device

    with TestClient(app) as client:
        response = client.get("/device")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_server_detector_uses_normalized_event_payload() -> None:
    from sentinel.ml.detector import ServerMLDetector

    class FakeModel:
        version = 7

        async def predict_proba(self, event_type: str, payload: dict[str, object]) -> float:
            assert event_type == "process"
            assert payload["pid"] == 42
            return 0.73

    class FakeRegistry:
        async def get(self, tenant_id: str | None):
            assert tenant_id == "tenant-1"
            return FakeModel()

    detector = ServerMLDetector(FakeRegistry())
    event = EndpointEvent(
        schema_version=1,
        event_id="evt-1",
        observed_at=datetime.now(timezone.utc),
        kind="process_start",
        host_id="host-1",
        pid=42,
        payload={"network_connections": 3},
    )
    result = await detector.detect(tenant_id="tenant-1", event=event)
    assert result is not None
    assert result.score == pytest.approx(0.73)
    assert result.model_version == 7
