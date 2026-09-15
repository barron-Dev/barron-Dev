from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sentinel.ml.runtime import ModelRegistry, registry
from sentinel.models.events import EndpointEvent


@dataclass(frozen=True, slots=True)
class MLDetection:
    score: float
    verdict: str
    model_version: int


class ServerMLDetector:
    """Runs the active tenant/global ONNX model against canonical events."""

    def __init__(self, model_registry: ModelRegistry = registry) -> None:
        self.registry = model_registry

    async def detect(self, *, tenant_id: str | None, event: EndpointEvent) -> MLDetection | None:
        model = await self.registry.get(tenant_id)
        if model is None:
            return None
        score = await model.predict_proba(event.ml_type(), self._payload(event))
        verdict = "high" if score >= 0.90 else "medium" if score >= 0.60 else "low"
        return MLDetection(score=score, verdict=verdict, model_version=model.version)

    @staticmethod
    def _payload(event: EndpointEvent) -> dict[str, Any]:
        payload = dict(event.payload)
        payload.update(
            {
                "pid": event.pid,
                "parent_pid": event.parent_pid,
                "image": event.image,
                "command_line": event.command_line,
                "remote_address": event.remote_address,
                "remote_port": event.remote_port,
            }
        )
        return payload


server_detector = ServerMLDetector()
