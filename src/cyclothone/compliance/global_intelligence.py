from __future__ import annotations

import asyncio
import logging
import re
from datetime import UTC, date, datetime
from typing import Any

import httpx

from cyclothone.storage.supabase_client import supabase

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"
USER_AGENT = "Cyclothone-CSA-Global-Intelligence/1.0"
BATCH_SIZE = 500


def _number(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if 0 <= parsed <= 1 else None


def _cve(value: Any) -> str | None:
    candidate = str(value or "").strip().upper()
    if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", candidate):
        return None
    return candidate


def normalize_kev(payload: dict[str, Any], synced_at: datetime) -> list[dict[str, Any]]:
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("cisa_kev_payload_missing_vulnerabilities")
    rows = []
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        cve_id = _cve(item.get("cveID"))
        if not cve_id:
            continue
        rows.append({
            "cve_id": cve_id,
            "cisa_kev_listed": True,
            "kev_date_added": item.get("dateAdded") or None,
            "kev_due_date": item.get("dueDate") or None,
            "known_ransomware_use": str(item.get("knownRansomwareCampaignUse", "")).lower() == "known",
            "kev_synced_at": synced_at.isoformat(),
        })
    return rows


def normalize_epss(items: list[dict[str, Any]], synced_at: datetime) -> list[dict[str, Any]]:
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        cve_id = _cve(item.get("cve"))
        score = _number(item.get("epss"))
        percentile = _number(item.get("percentile"))
        if not cve_id or score is None or percentile is None:
            continue
        rows.append({
            "cve_id": cve_id,
            "epss_score": score,
            "epss_percentile": percentile,
            "epss_as_of": item.get("date") or synced_at.date().isoformat(),
            "epss_synced_at": synced_at.isoformat(),
        })
    return rows


async def _upsert(rows: list[dict[str, Any]]) -> int:
    written = 0
    for offset in range(0, len(rows), BATCH_SIZE):
        batch = rows[offset:offset + BATCH_SIZE]

        async def _write():
            return await (await supabase._ensure()).table("csa_global_exploit_intel").upsert(
                batch, on_conflict="cve_id"
            ).execute()

        await supabase._retry(_write, attempts=2)
        written += len(batch)
    return written


async def sync_cisa_kev(client: httpx.AsyncClient, synced_at: datetime) -> dict[str, Any]:
    response = await client.get(CISA_KEV_URL, headers={"User-Agent": USER_AGENT})
    response.raise_for_status()
    payload = response.json()
    rows = normalize_kev(payload, synced_at)
    if not rows:
        raise ValueError("cisa_kev_feed_returned_no_valid_records")
    written = await _upsert(rows)
    return {"records_seen": len(payload.get("vulnerabilities", [])), "records_upserted": written,
            "source_version": str(payload.get("catalogVersion") or "unknown"),
            "source_as_of": payload.get("dateReleased")}


async def sync_first_epss(client: httpx.AsyncClient, synced_at: datetime) -> dict[str, Any]:
    offset = 0
    rows: list[dict[str, Any]] = []
    total: int | None = None
    while total is None or offset < total:
        response = await client.get(FIRST_EPSS_URL, params={"limit": 1000, "offset": offset},
                                    headers={"User-Agent": USER_AGENT})
        response.raise_for_status()
        payload = response.json()
        data = payload.get("data")
        if not isinstance(data, list):
            raise ValueError("first_epss_payload_missing_data")
        rows.extend(normalize_epss(data, synced_at))
        total = int(payload.get("total") or len(data))
        offset += len(data)
        if not data or len(data) < 1000:
            break
        if offset > 2_000_000:
            raise ValueError("first_epss_pagination_safety_limit")
    if not rows:
        raise ValueError("first_epss_feed_returned_no_valid_records")
    written = await _upsert(rows)
    return {"records_seen": len(rows), "records_upserted": written,
            "source_version": "FIRST EPSS API", "source_as_of": synced_at.date().isoformat()}


async def _record_run(source: str, result: dict[str, Any] | None, error: str | None,
                      started: datetime, completed: datetime) -> None:
    row = {
        "source": source,
        "started_at": started.isoformat(),
        "completed_at": completed.isoformat(),
        "status": "failed" if error else "succeeded",
        "records_seen": int((result or {}).get("records_seen", 0)),
        "records_upserted": int((result or {}).get("records_upserted", 0)),
        "source_version": (result or {}).get("source_version"),
        "source_as_of": (result or {}).get("source_as_of"),
        "error_code": error,
        "metadata": {"source_url": CISA_KEV_URL if source == "cisa_kev" else FIRST_EPSS_URL},
    }

    async def _insert():
        return await (await supabase._ensure()).table("csa_global_intel_sync_runs").insert(row).execute()

    await supabase._retry(_insert, attempts=2)


async def sync_global_intelligence() -> dict[str, Any]:
    """Fetch official public feeds; failed sources remain visibly failed, never clean."""
    started = datetime.now(UTC)
    results: dict[str, Any] = {}
    errors: dict[str, str] = {}
    timeout = httpx.Timeout(60.0, connect=15.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for source, operation in (("cisa_kev", sync_cisa_kev), ("first_epss", sync_first_epss)):
            source_started = datetime.now(UTC)
            try:
                result = await operation(client, source_started)
                results[source] = result
                await _record_run(source, result, None, source_started, datetime.now(UTC))
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                errors[source] = type(exc).__name__
                logger.exception("CSA global intelligence sync failed for %s", source)
                try:
                    await _record_run(source, None, type(exc).__name__, source_started, datetime.now(UTC))
                except Exception:
                    logger.exception("unable to persist CSA feed failure state for %s", source)
    return {"started_at": started.isoformat(), "completed_at": datetime.now(UTC).isoformat(),
            "sources": results, "errors": errors, "complete": not errors and len(results) == 2}
