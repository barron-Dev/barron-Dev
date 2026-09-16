from __future__ import annotations

import asyncio
import logging

from sentinel.physical.correlator import PhysicalCorrelator
from sentinel.storage.supabase_client import supabase

logger = logging.getLogger(__name__)


class PhysicalScheduler:
    PULL_INTERVAL = 300

    def __init__(self) -> None:
        self.correlator = PhysicalCorrelator()
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._loop(), name="physical-correlator")

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
                for tenant in await self._tenants():
                    await self.correlator.run_window(tenant["id"], 5)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("physical correlation cycle failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.PULL_INTERVAL)
            except asyncio.TimeoutError:
                pass

    async def _tenants(self) -> list[dict]:
        async def _do():
            client = await supabase._ensure()
            return await client.table("tenants").select("id").execute()
        try:
            return list((await supabase._retry(_do)).data or [])
        except Exception:
            return []
