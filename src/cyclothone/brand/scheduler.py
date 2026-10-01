from __future__ import annotations

import asyncio
import logging
import time

from cyclothone.brand.apps import AppStoreMonitor
from cyclothone.brand.ct_logs import CTLogMonitor
from cyclothone.brand.social import SocialMonitor
from cyclothone.brand.typosquat import TyposquatScanner
from cyclothone.storage.supabase_client import supabase

logger = logging.getLogger(__name__)


class BrandScheduler:
    CT_INTERVAL = 3600
    TYPOSQUAT_INTERVAL = 86400
    SOCIAL_INTERVAL = 86400
    STARTUP_DELAY_SECONDS = 120

    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._last_typo = 0.0
        self._last_social = 0.0

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._loop(), name="cyclothone-brand")

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _brands(self) -> list[dict]:
        async def query():
            return await (
                await supabase._ensure()
            ).table("brands").select("*").eq("enabled", True).execute()

        try:
            return list((await supabase._retry(query, attempts=2)).data or [])
        except Exception:
            logger.exception("brand configuration query failed")
            return []

    async def _scan(self, scanner) -> None:
        for brand in await self._brands():
            try:
                await scanner.scan_brand(brand)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("brand scan failed id=%s", brand.get("id"))

    async def _loop(self) -> None:
        try:
            await asyncio.wait_for(
                self._stop.wait(), timeout=self.STARTUP_DELAY_SECONDS
            )
            return
        except asyncio.TimeoutError:
            pass

        while not self._stop.is_set():
            try:
                await CTLogMonitor().match_brands()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("brand CT tick failed")

            now = time.time()

            if now - self._last_typo >= self.TYPOSQUAT_INTERVAL:
                await self._scan(TyposquatScanner())
                self._last_typo = now

            if now - self._last_social >= self.SOCIAL_INTERVAL:
                await self._scan(SocialMonitor())
                await self._scan(AppStoreMonitor())
                self._last_social = now

            try:
                await asyncio.wait_for(
                    self._stop.wait(), timeout=self.CT_INTERVAL
                )
            except asyncio.TimeoutError:
                pass
