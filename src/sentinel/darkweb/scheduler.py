from __future__ import annotations

import asyncio
import logging
import os
import time

from sentinel.darkweb.matcher import DarkWebMatcher
from sentinel.darkweb.pullers import GitHubCodeMonitor, HIBPPuller, PastePublicMonitor, RansomwatchPuller, TelegramPublicMonitor

logger = logging.getLogger(__name__)

class DarkWebScheduler:
    GLOBAL_INTERVAL = 15 * 60
    DOMAIN_INTERVAL = 6 * 3600
    STARTUP_DELAY = 30

    def __init__(self) -> None:
        self.matcher = DarkWebMatcher()
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._last_domain = 0.0

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._loop(), name="sentinel-darkweb")

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
        for pull in (RansomwatchPuller(), PastePublicMonitor()):
            try:
                await self._ingest(await pull.pull())
            except Exception:
                logger.exception("dark web source failed: %s", type(pull).__name__)
        channels = [x.strip() for x in os.getenv("SENTINEL_DW_TELEGRAM_CHANNELS", "").split(",") if x.strip()]
        if channels:
            await self._ingest(await TelegramPublicMonitor(channels).pull())

    async def _domain_tick(self) -> None:
        domains = await self._tenant_domains()
        hibp_key = os.getenv("SENTINEL_HIBP_KEY", "").strip()
        github_token = os.getenv("SENTINEL_GITHUB_TOKEN", "").strip()
        for domain in domains:
            if hibp_key:
                await self._ingest(await HIBPPuller(hibp_key).pull_domain(domain))
            if github_token:
                await self._ingest(await GitHubCodeMonitor(github_token).pull_domain(domain))

    async def _ingest(self, findings: list) -> None:
        for finding in findings[:2000]:
            if self._stop.is_set():
                return
            await self.matcher.process({
                "source_id": finding.source_id, "kind": finding.kind,
                "matched_value": finding.matched_value, "context": finding.context,
                "severity": finding.severity, "source_url": finding.source_url,
                "metadata": finding.metadata,
            })

    async def _tenant_domains(self) -> list[str]:
        from sentinel.storage.supabase_client import supabase
        async def _do():
            return await (await supabase._ensure()).table("dw_watchlist").select("value").eq("kind", "domain").execute()
        try:
            rows = (await supabase._retry(_do, attempts=1)).data or []
            return sorted({str(row["value"]).strip().lower() for row in rows if row.get("value")})
        except Exception:
            logger.debug("dark web domain watchlist unavailable", exc_info=True)
            return []
