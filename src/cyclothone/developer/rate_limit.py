from __future__ import annotations

from datetime import UTC, datetime

from sentinel.storage.supabase_client import supabase


async def consume(subject: str, limit: int, *, window_seconds: int = 60) -> bool:
    if limit < 1 or window_seconds < 1:
        raise ValueError("limit and window_seconds must be positive")
    now = datetime.now(UTC)
    epoch = int(now.timestamp())
    start = datetime.fromtimestamp(epoch - (epoch % window_seconds), UTC)
    return bool(await supabase.rpc("consume_api_rate", {"p_subject": subject, "p_bucket_start": start.isoformat(), "p_limit": limit}))


async def record_usage(tenant_id: str, app_id: str | None, *, requests: int = 1, tokens: int = 0, bytes_in: int = 0, bytes_out: int = 0) -> None:
    if min(requests, tokens, bytes_in, bytes_out) < 0:
        raise ValueError("usage values cannot be negative")
    await supabase.rpc("increment_api_usage", {
        "p_tenant_id": tenant_id, "p_app_id": app_id, "p_usage_date": datetime.now(UTC).date().isoformat(),
        "p_requests": requests, "p_tokens": tokens, "p_bytes_in": bytes_in, "p_bytes_out": bytes_out,
    })
