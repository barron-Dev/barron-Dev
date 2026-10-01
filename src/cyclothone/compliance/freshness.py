from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

# Default freshness for automated telemetry collectors. Historical observation
# windows remain independent from collector freshness.
DEFAULT_FRESHNESS = timedelta(hours=24)


def is_stale(valid_until: str | datetime | None, now: datetime | None = None) -> bool:
    if valid_until is None:
        return True
    current = now or datetime.now(UTC)
    if isinstance(valid_until, datetime):
        value = valid_until
    else:
        try:
            value = datetime.fromisoformat(str(valid_until).replace("Z", "+00:00"))
        except ValueError:
            return True
    if value.tzinfo is None:
        return True
    return value <= current


def coverage_summary(rows: list[dict[str, Any]], expected_sources: list[str]) -> dict[str, Any]:
    by_source: dict[str, dict[str, Any]] = {}
    for row in rows:
        source = str(row.get("source_ref", ""))
        if source and source not in by_source:
            by_source[source] = row
    sources = []
    fresh = failed = stale_or_missing = 0
    for source in expected_sources:
        row = by_source.get(source)
        stale = row is None or is_stale(row.get("valid_until"))
        status = str(row.get("status")) if row else "missing"
        if status == "failed":
            failed += 1
        if stale:
            stale_or_missing += 1
        if status in {"collected", "empty"} and not stale:
            fresh += 1
        sources.append({"source_ref": source, "status": status, "stale": stale, "row_count": int(row.get("row_count", 0)) if row else 0, "error_code": row.get("error_code") if row else None})
    return {"expected": len(expected_sources), "fresh": fresh, "failed": failed, "stale_or_missing": stale_or_missing, "sources": sources}
