from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta

from sentinel.compliance.evaluator import ComplianceEvaluator
from sentinel.storage.supabase_client import supabase

logger = logging.getLogger(__name__)

class ComplianceScheduler:
    EVAL_INTERVAL_SECONDS = 6 * 3600
    STALE_INTERVAL_SECONDS = 3600
    STARTUP_DELAY_SECONDS = 120

    def __init__(self) -> None:
        self._tasks: list[asyncio.Task] = []
        self._stop = asyncio.Event()

    def start(self) -> None:
        if self._tasks and any(not t.done() for t in self._tasks):
            return
        self._stop.clear()
        self._tasks = [asyncio.create_task(self._eval_loop(), name="sentinel-compliance-eval"), asyncio.create_task(self._stale_loop(), name="sentinel-compliance-stale")]

    async def stop(self) -> None:
        self._stop.set()
        tasks, self._tasks = self._tasks, []
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def _eval_loop(self) -> None:
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=self.STARTUP_DELAY_SECONDS)
            return
        except asyncio.TimeoutError:
            pass
        while not self._stop.is_set():
            try:
                await self._eval_all()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("continuous compliance evaluation failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.EVAL_INTERVAL_SECONDS)
            except asyncio.TimeoutError:
                pass

    async def _stale_loop(self) -> None:
        while not self._stop.is_set():
            try:
                async def _rpc():
                    return await (await supabase._ensure()).rpc("mark_compliance_evidence_stale", {}).execute()
                await supabase._retry(_rpc, attempts=1)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.debug("compliance stale sweep failed", exc_info=True)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.STALE_INTERVAL_SECONDS)
            except asyncio.TimeoutError:
                pass

    async def _eval_all(self) -> None:
        async def _tenants():
            return await (await supabase._ensure()).table("tenants").select("id").execute()
        tenants = (await supabase._retry(_tenants, attempts=2)).data or []
        evaluator = ComplianceEvaluator()
        now = datetime.now(UTC)
        start = now - timedelta(days=1)
        for tenant in tenants:
            for framework in ("soc2", "iso27001", "gdpr", "hipaa"):
                try:
                    await evaluator.evaluate(tenant["id"], framework, start, now)
                except Exception:
                    logger.warning("compliance evaluation failed for tenant=%s framework=%s", tenant["id"], framework, exc_info=True)
