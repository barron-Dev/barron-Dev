from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EndpointEvent(BaseModel):
    """Server representation of the agent's EndpointEvent JSON contract."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(ge=1)
    event_id: str = Field(min_length=1, max_length=256)
    observed_at: datetime
    kind: str = Field(min_length=1, max_length=128)
    host_id: str = Field(min_length=1, max_length=256)
    pid: int | None = Field(default=None, ge=0)
    parent_pid: int | None = Field(default=None, ge=0)
    image: str | None = None
    command_line: str | None = None
    remote_address: str | None = None
    remote_port: int | None = Field(default=None, ge=0, le=65535)
    payload: dict[str, Any] = Field(default_factory=dict)

    def ml_type(self) -> str:
        if self.kind in {"process_start", "process_stop"}:
            return "process"
        if self.kind == "network_connect":
            return "network"
        if self.kind == "file_activity":
            return "file"
        return "unknown"
