from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    url: str = Field(min_length=4, max_length=4096)
    wait_ms: int = Field(default=5000, ge=500, le=20_000)
    screenshot: bool = True


class ScanSignal(BaseModel):
    name: str
    detail: str = ""
    weight: float = Field(default=0.0, ge=0.0, le=1.0)


class ScanResponse(BaseModel):
    final_url: str
    redirects: list[str]
    screenshot_b64: str | None = None
    verdict: str
    score: float
    signals: list[ScanSignal]
    downloads: list[dict[str, Any]] = Field(default_factory=list)
    duration_ms: int = 0
    console_tail: list[str] = Field(default_factory=list)
