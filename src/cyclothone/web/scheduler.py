from __future__ import annotations

import asyncio
import logging
import time

from cyclothone.web.orchestrator import WebIntelligenceOrchestrator

logger = logging.getLogger(__name__)


class WebIntelligenceScheduler:
    """Runs configured web targets according to each target's persisted interval."""

    STARTUP_DELAY = 60
    TICK_SECONDS = 60

    def __init__(self) -> None:
        self.orchestrator = WebIntelligenceOrchestrator()
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._loop(), name="cyclothone-web-intel")

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
            started = time.monotonic()
            try:
                result = await self.orchestrator.crawl_targets()
                logger.info("web intelligence tick result=%s", result)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("web intelligence tick failed")
            elapsed = time.monotonic() - started
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=max(1.0, self.TICK_SECONDS - elapsed))
            except asyncio.TimeoutError:
                pass
