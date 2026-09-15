from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EndpointEvent(BaseModel):
    """Canonical server representation of the existing agent event contract."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(ge=1)
    event_id: str = Field(min_length=1, max_length=256)
    observed_at: datetime
    event_type: str = Field(min_length=1, max_length=128)
    device_id: str | None = None
    pid: int | None = Field(default=None, ge=0)
    parent_pid: int | None = Field(default=None, ge=0)
    image: str | None = None
    command_line: str | None = None
    remote_address: str | None = None
    remote_port: int | None = Field(default=None, ge=0, le=65535)
    payload: dict[str, Any] = Field(default_factory=dict)

    def ml_type(self) -> str:
        if self.event_type in {"process_start", "process_stop"}:
            return "process"
        if self.event_type == "network_connect":
            return "network"
        if self.event_type == "file_activity":
            return "file"
        return "unknown"
