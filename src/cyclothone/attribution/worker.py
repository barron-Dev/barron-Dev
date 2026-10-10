from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from cyclothone.attribution.attack_catalog import sync_attack_catalogue
from cyclothone.attribution.cluster import assemble_activity_cluster
from cyclothone.attribution.dispatcher import dispatch_pending_attribution_alerts
from cyclothone.attribution.service import assess_activity_cluster
from cyclothone.storage.supabase_client import supabase

logger = logging.getLogger(__name__)


async def process_attribution_job(job: dict[str, Any]) -> dict[str, Any]:
    tenant_id, watchlist_id = str(job.get("tenant_id") or ""), str(job.get("watchlist_id") or "")
    if not tenant_id or not watchlist_id:
        raise ValueError("tenant_and_watchlist_required")
    client = await supabase._ensure()
    since = (datetime.now(UTC) - timedelta(days=30)).isoformat()
    result = await client.table("dw_findings").select(
        "id,source_id,content_hash,kind,matched_value,context,source_url,source_metadata,severity,first_seen,tenant_id,watchlist_id"
    ).eq("tenant_id", tenant_id).eq("watchlist_id", watchlist_id).gte("first_seen", since).order("first_seen", desc=True).limit(1000).execute()
    rows = result.data or []
    if not rows:
        return {"status": "empty", "count": 0}
    records = []
    for row in rows:
        metadata = row.get("source_metadata") or {}
        records.append({
            "record_id": str(row["id"]), "source_name": row.get("source_id"),
            "evidence_hash": row.get("content_hash"), "kind": row.get("kind"),
            "indicator_hash": row.get("content_hash"), "source_url": row.get("source_url"),
            "observed_at": row.get("first_seen"), "context": row.get("context"),
            "evidence_type": "INFRASTRUCTURE" if row.get("kind") in {"domain", "ip"} else "SOURCE_REPORT",
            "infrastructure": metadata.get("infrastructure") if isinstance(metadata, dict) else {},
            "attack_techniques": metadata.get("attack_techniques", []) if isinstance(metadata, dict) else [],
            "capec_ids": metadata.get("capec_ids", []) if isinstance(metadata, dict) else [],
            "malware_families": metadata.get("malware_families", []) if isinstance(metadata, dict) else [],
            "target_sectors": metadata.get("target_sectors", []) if isinstance(metadata, dict) else [],
            "target_regions": metadata.get("target_regions", []) if isinstance(metadata, dict) else [],
            "observed_actions": metadata.get("observed_actions", []) if isinstance(metadata, dict) else [],
            "confidence": 0.5,
        })
    cluster = assemble_activity_cluster(records, tenant_id=tenant_id, cluster_key=watchlist_id)
    assessment = await assess_activity_cluster(cluster)
    return {"activity_cluster_id": cluster["activity_cluster_id"], **assessment, "evidence_count": len(records)}


async def process_pending_attribution_jobs(limit: int = 25) -> int:
    client = await supabase._ensure()
    claimed = await client.rpc("claim_dw_attribution_jobs", {"p_limit": max(1, min(100, int(limit)))})
    jobs = claimed or []
    processed = 0
    for job in jobs:
        job_id = str(job.get("job_id") or "")
        try:
            await process_attribution_job(job)
            await client.rpc("finish_dw_attribution_job", {"p_job_id": job_id, "p_error_code": None})
            processed += 1
        except Exception as exc:
            logger.warning("attribution job failed job_id=%s error=%s", job_id, type(exc).__name__)
            await client.rpc("finish_dw_attribution_job", {"p_job_id": job_id, "p_error_code": type(exc).__name__[:80]})
    return processed


class AttributionWorker:
    def __init__(self, interval_seconds: int = 15) -> None:
        self.interval_seconds = max(5, min(300, interval_seconds))
        self.enabled = os.getenv("CYCLOTHONE_DW_ATTRIBUTION_ENABLED", "false").strip().lower() in {"1", "true", "yes"}
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._last_catalogue_sync = 0.0
        self._last_retention_sweep = 0.0

    def start(self) -> None:
        if not self.enabled:
            logger.info("attribution worker disabled until CYCLOTHONE_DW_ATTRIBUTION_ENABLED=true")
            return
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._loop(), name="cyclothone-attribution-worker")

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                await process_pending_attribution_jobs()
                try:
                    await dispatch_pending_attribution_alerts()
                except Exception as exc:
                    logger.warning("attribution alert dispatch failed error=%s", type(exc).__name__)
                if time.monotonic() - self._last_retention_sweep >= 86400:
                    try:
                        await supabase.rpc("purge_dw_attribution_delivery_history", {"p_retention_days": 90})
                    except Exception as exc:
                        logger.warning("attribution retention sweep failed error=%s", type(exc).__name__)
                    self._last_retention_sweep = time.monotonic()
                if time.monotonic() - self._last_catalogue_sync >= 21600:
                    try:
                        await sync_attack_catalogue()
                    except Exception as exc:
                        logger.warning("ATT&CK catalogue sync failed error=%s", type(exc).__name__)
                    self._last_catalogue_sync = time.monotonic()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("attribution worker cycle failed error=%s", type(exc).__name__)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval_seconds)
            except asyncio.TimeoutError:
                pass
