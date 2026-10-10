from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import UTC, datetime
from uuid import uuid4

from cyclothone.darkweb.matcher import DarkWebMatcher
from cyclothone.darkweb.pullers import GitHubCodeMonitor, HIBPPuller, PastePublicMonitor, RansomwatchPuller, TelegramPublicMonitor
from cyclothone.storage.supabase_client import supabase
from cyclothone.streaming.pipeline import ChangeEventPipeline

logger = logging.getLogger(__name__)


def _progress_percent(processed: int, total: int) -> int:
    """Calculate progress from actual processed records, never elapsed time."""
    if total <= 0:
        return 100 if processed == 0 else 0
    return min(100, max(0, int((processed / total) * 100)))


class DarkWebScheduler:
    GLOBAL_INTERVAL = 15 * 60
    DOMAIN_INTERVAL = 6 * 3600
    STARTUP_DELAY = 30

    def __init__(self) -> None:
        self.matcher = DarkWebMatcher()
        self.change_pipeline = ChangeEventPipeline()
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._last_domain = 0.0

    def start(self) -> None:
        self.change_pipeline.start()
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._loop(), name="cyclothone-darkweb")

    async def stop(self) -> None:
        self._stop.set()
        await self.change_pipeline.stop()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _loop(self) -> None:
        await asyncio.sleep(self.STARTUP_DELAY)
        while not self._stop.is_set():
            try:
                await self._global_tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("dark web global tick failed")
            if time.monotonic() - self._last_domain >= self.DOMAIN_INTERVAL:
                try:
                    await self._domain_tick()
                    self._last_domain = time.monotonic()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("dark web domain tick failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.GLOBAL_INTERVAL)
            except asyncio.TimeoutError:
                pass

    async def _global_tick(self) -> None:
        enabled = await self._enabled_sources()
        for pull in (RansomwatchPuller(), PastePublicMonitor()):
            if pull.SOURCE in enabled:
                await self._run_pull(pull.SOURCE, pull.pull, target_label=pull.SOURCE)
        channels_value = (os.getenv("CYCLOTHONE_DW_TELEGRAM_CHANNELS") or os.getenv("SENTINEL_DW_TELEGRAM_CHANNELS") or "").strip()
        channels = [x.strip() for x in channels_value.split(",") if x.strip()]
        if channels and "telegram_public" in enabled:
            for channel in channels:
                monitor = TelegramPublicMonitor([channel])
                await self._run_pull(monitor.SOURCE, monitor.pull, target_label=f"@{channel}")

    async def _domain_tick(self) -> None:
        domains = await self._tenant_domains()
        hibp_key = (os.getenv("CYCLOTHONE_HIBP_KEY") or os.getenv("SENTINEL_HIBP_KEY") or "").strip()
        github_token = (os.getenv("CYCLOTHONE_GITHUB_TOKEN") or os.getenv("SENTINEL_GITHUB_TOKEN") or "").strip()
        enabled = await self._enabled_sources()
        for domain in domains:
            if hibp_key and "hibp" in enabled:
                puller = HIBPPuller(hibp_key)
                await self._run_pull(puller.SOURCE, lambda p=puller, d=domain: p.pull_domain(d), target_label=domain)
            if github_token and "github_code" in enabled:
                monitor = GitHubCodeMonitor(github_token)
                await self._run_pull(monitor.SOURCE, lambda m=monitor, d=domain: m.pull_domain(d), target_label=domain)

    async def _run_pull(self, source_id: str, pull, *, target_label: str | None = None) -> None:
        started = time.monotonic()
        steps = [
            {"key": "source_request", "label": "Request source data", "status": "running", "progress_percent": 0, "detail": "Source request started."},
            {"key": "normalize", "label": "Normalize returned records", "status": "pending", "progress_percent": 0, "detail": "Waiting for source response."},
            {"key": "watchlist_match", "label": "Match authorized watch targets", "status": "pending", "progress_percent": 0, "detail": "Waiting for normalized records."},
            {"key": "evidence_persist", "label": "Persist findings and evidence", "status": "pending", "progress_percent": 0, "detail": "Waiting for watchlist matching."},
            {"key": "change_event", "label": "Record change-detection events", "status": "pending", "progress_percent": 0, "detail": "Waiting for finding processing."},
        ]
        run_id = await self._begin_run(source_id, target_label=target_label, process_steps=steps)
        try:
            findings = (await pull())[:2000]
            steps[0].update({"status": "completed", "progress_percent": 100, "detail": "Source request returned successfully."})
            steps[1].update({"status": "completed", "progress_percent": 100, "detail": f"{len(findings)} records returned after normalization."})
            steps[2].update({"status": "running", "detail": "Matching returned records against exact authorized watch targets."})
            await self._update_run(run_id, {
                "stage": "records_normalized", "progress_percent": 0,
                "discovered_count": len(findings), "processed_count": 0,
                "matched_count": 0, "alert_count": 0, "error_count": 0,
                "process_steps": steps, "detail": f"{len(findings)} records returned; matching has started.",
            })
            result = await self._ingest(findings, run_id=run_id, process_steps=steps)
            source_status = "degraded" if result["errors"] else "ok"
            await self._mark_source(source_id, source_status)
            await self._update_run(run_id, {
                "status": source_status, "stage": "completed", "progress_percent": 100,
                "processed_count": len(findings), "matched_count": result["matched"],
                "alert_count": result["alerts"], "error_count": result["errors"],
                "process_steps": steps,
                "detail": "Processing cycle finished." if not result["errors"] else "Cycle finished with recorded processing errors.",
                "completed_at": datetime.now(UTC).isoformat(),
            })
            logger.info(
                "dark web source=%s completed findings=%d matched=%d alerts=%d errors=%d duration_ms=%d",
                source_id, len(findings), result["matched"], result["alerts"], result["errors"], int((time.monotonic() - started) * 1000),
            )
        except asyncio.CancelledError:
            await self._update_run(run_id, {"status": "cancelled", "stage": "cancelled", "detail": "Processing was cancelled."})
            raise
        except Exception:
            await self._mark_source(source_id, "failed")
            await self._update_run(run_id, {
                "status": "failed", "stage": "failed",
                "process_steps": [{**step, "status": "failed" if step["status"] == "running" else step["status"], "detail": "Step failed; inspect service logs for the cause." if step["status"] == "running" else step["detail"]} for step in steps],
                "detail": "Source pull or processing failed; inspect service logs for the cause.",
                "completed_at": datetime.now(UTC).isoformat(),
            })
            logger.exception("dark web source failed: %s", source_id)

    async def _begin_run(self, source_id: str, *, target_label: str | None = None, process_steps: list[dict] | None = None) -> str | None:
        run_id = str(uuid4())
        async def _do():
            return await (await supabase._ensure()).table("dw_source_runs").insert({
                "id": run_id, "source_id": source_id, "target_label": target_label,
                "process_steps": process_steps or [], "status": "running",
                "stage": "connecting_to_source", "progress_percent": 0,
                "detail": "Source pull started.", "started_at": datetime.now(UTC).isoformat(),
            }).execute()
        try:
            await supabase._retry(_do, attempts=1)
            return run_id
        except Exception:
            logger.warning("source-run telemetry unavailable; migration may be pending", exc_info=True)
            return None

    async def _update_run(self, run_id: str | None, fields: dict) -> None:
        if not run_id:
            return
        patch = {**fields, "updated_at": datetime.now(UTC).isoformat()}
        async def _do():
            return await (await supabase._ensure()).table("dw_source_runs").update(patch).eq("id", run_id).execute()
        try:
            await supabase._retry(_do, attempts=1)
        except Exception:
            logger.warning("unable to persist source-run progress", exc_info=True)

    async def _ingest(self, findings: list, *, run_id: str | None = None, process_steps: list[dict] | None = None) -> dict[str, int]:
        matched = alerts = errors = 0
        total = len(findings)
        steps = process_steps if process_steps is not None else []
        steps_by_key = {step["key"]: step for step in steps}
        for index, finding in enumerate(findings, start=1):
            if self._stop.is_set():
                return {"matched": matched, "alerts": alerts, "errors": errors}
            try:
                result = await self.matcher.process({
                    "source_id": finding.source_id, "kind": finding.kind,
                    "matched_value": finding.matched_value, "context": finding.context,
                    "severity": finding.severity, "source_url": finding.source_url,
                    "metadata": finding.metadata,
                })
            except asyncio.CancelledError:
                raise
            except Exception:
                errors += 1
                logger.exception("dark web matcher raised unexpectedly source=%s", finding.source_id)
                result = {"matched": 0, "alerts": 0, "errors": 1}
            matched += int(result.get("matched", 0))
            alerts += int(result.get("alerts", 0))
            errors += int(result.get("errors", 0))
            try:
                await self.change_pipeline.enqueue_finding(finding)
            except asyncio.CancelledError:
                raise
            except Exception:
                errors += 1
                logger.warning("dark web change-event outbox write failed for source=%s", finding.source_id, exc_info=True)
            if index == total or index % 25 == 0:
                progress = _progress_percent(index, total)
                if "watchlist_match" in steps_by_key:
                    steps_by_key["watchlist_match"].update({
                        "status": "completed" if index == total else "running",
                        "progress_percent": progress,
                        "detail": f"Processed {index} of {total} returned records; {matched} target matches.",
                    })
                if "evidence_persist" in steps_by_key:
                    steps_by_key["evidence_persist"].update({
                        "status": "completed" if index == total else "running",
                        "progress_percent": progress,
                        "detail": f"Processed {index} of {total} records; {alerts} alerts recorded.",
                    })
                if "change_event" in steps_by_key:
                    steps_by_key["change_event"].update({
                        "status": "completed" if index == total else "running",
                        "progress_percent": progress,
                        "detail": f"Change events attempted for {index} of {total} records.",
                    })
                await self._update_run(run_id, {
                    "stage": "matching_and_persisting", "progress_percent": min(progress, 100),
                    "process_steps": steps,
                    "processed_count": index, "matched_count": matched,
                    "alert_count": alerts, "error_count": errors,
                    "detail": f"Processed {index} of {total} returned findings.",
                })
        if total == 0:
            for key in ("watchlist_match", "evidence_persist", "change_event"):
                if key in steps_by_key:
                    steps_by_key[key].update({"status": "completed", "progress_percent": 100, "detail": "No records returned; no records were fabricated."})
            await self._update_run(run_id, {
                "stage": "matching_and_persisting", "progress_percent": 100,
                "process_steps": steps, "processed_count": 0, "detail": "Source returned zero findings; no findings were fabricated.",
            })
        return {"matched": matched, "alerts": alerts, "errors": errors}

    async def _enabled_sources(self) -> set[str]:
        async def _do():
            return await (await supabase._ensure()).table("dw_sources").select("id").eq("enabled", True).execute()
        try:
            rows = (await supabase._retry(_do, attempts=1)).data or []
            return {str(row["id"]) for row in rows if row.get("id")}
        except Exception:
            logger.warning("dark web source configuration unavailable; failing closed", exc_info=True)
            return set()

    async def _mark_source(self, source_id: str, status: str) -> None:
        async def _do():
            return await (await supabase._ensure()).table("dw_sources").update({
                "last_pull_at": datetime.now(UTC).isoformat(),
                "last_status": status,
            }).eq("id", source_id).execute()
        try:
            await supabase._retry(_do, attempts=1)
        except Exception:
            logger.warning("unable to persist dark web source health: %s", source_id, exc_info=True)

    async def _tenant_domains(self) -> list[str]:
        async def _do():
            return await (await supabase._ensure()).table("dw_watchlist").select("value").eq("kind", "domain").execute()
        try:
            rows = (await supabase._retry(_do, attempts=1)).data or []
            return sorted({str(row["value"]).strip().lower() for row in rows if row.get("value")})
        except Exception:
            logger.debug("dark web domain watchlist unavailable", exc_info=True)
            return []
