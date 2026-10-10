from __future__ import annotations

import os
from datetime import UTC, datetime


_REQUIRED_ENV: dict[str, tuple[str, ...]] = {
    "hibp": ("CYCLOTHONE_HIBP_KEY", "SENTINEL_HIBP_KEY"),
    "github_code": ("CYCLOTHONE_GITHUB_TOKEN", "SENTINEL_GITHUB_TOKEN"),
    "telegram_public": ("CYCLOTHONE_DW_TELEGRAM_CHANNELS", "SENTINEL_DW_TELEGRAM_CHANNELS"),
}


def _configured(source_id: str, environ: dict[str, str]) -> bool:
    names = _REQUIRED_ENV.get(source_id, ())
    if not names:
        return True
    return any(environ.get(name, "").strip() for name in names)


def source_health(
    row: dict,
    *,
    now: datetime | None = None,
    environ: dict[str, str] | None = None,
) -> dict:
    """Return truthful operational status without exposing secret values."""
    env = os.environ if environ is None else environ
    source_id = str(row.get("id") or "")
    enabled = bool(row.get("enabled"))
    last_status = str(row.get("last_status") or "").lower() or None
    last_pull = row.get("last_pull_at")
    interval = max(60, int(row.get("poll_interval_seconds") or 900))
    result = {
        "id": source_id,
        "name": row.get("name"),
        "kind": row.get("kind"),
        "enabled": enabled,
        "last_pull_at": last_pull,
        "last_status": last_status,
        "poll_interval_seconds": interval,
        "health": "disabled",
        "configuration_ready": _configured(source_id, env),
    }
    if not enabled:
        return result
    if not result["configuration_ready"]:
        result["health"] = "blocked_missing_credentials"
        return result
    if not last_pull:
        result["health"] = "not_yet_verified"
        return result
    if last_status not in {"ok", "degraded", "failed"}:
        result["health"] = "not_yet_verified"
        return result
    if last_status == "failed":
        result["health"] = "failed"
        return result
    if last_status == "degraded":
        result["health"] = "degraded"
        return result
    try:
        parsed = datetime.fromisoformat(str(last_pull).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        current = now or datetime.now(UTC)
        if current.tzinfo is None:
            current = current.replace(tzinfo=UTC)
        if (current - parsed).total_seconds() > max(interval * 2, 3600):
            result["health"] = "stale"
            return result
    except (TypeError, ValueError):
        result["health"] = "not_yet_verified"
        return result
    result["health"] = "ok"
    return result
