from __future__ import annotations

import asyncio
import logging

from sentinel.ml.train import NotEnoughData, run_training

logger = logging.getLogger(__name__)


class TrainingScheduler:
    """Periodic tenant retraining; model activation is metric-gated."""

    def __init__(self, interval_hours: int = 24, min_auc_delta: float = 0.005) -> None:
        if interval_hours < 1:
            raise ValueError("interval_hours must be >= 1")
        if min_auc_delta < 0:
            raise ValueError("min_auc_delta must be >= 0")
        self.interval = interval_hours * 3600
        self.min_auc_delta = min_auc_delta
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._loop(), name="sentinel-ml-training")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None

    async def _loop(self) -> None:
        # Give application startup time to initialize storage/auth dependencies.
        await asyncio.sleep(60)
        while True:
            try:
                await self._tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("ML training scheduler tick failed")
            await asyncio.sleep(self.interval)

    async def _tick(self) -> None:
        for tenant_id in await self._active_tenants():
            try:
                result = await run_training(tenant_id)
                await self._maybe_activate(tenant_id, result)
            except NotEnoughData as exc:
                logger.info("tenant %s: training skipped: %s", tenant_id, exc)
            except Exception:
                logger.exception("tenant %s: training failed", tenant_id)

    async def _active_tenants(self) -> list[str]:
        from sentinel.storage.supabase_client import supabase

        async def _do():
            client = await supabase._ensure()
            return await client.table("labels").select("tenant_id").limit(5000).execute()

        try:
            response = await supabase._retry(_do, attempts=2)
        except Exception as exc:
            logger.warning("could not enumerate ML tenants: %s", exc)
            return []
        return sorted({str(row["tenant_id"]) for row in (response.data or []) if row.get("tenant_id")})

    async def _maybe_activate(self, tenant_id: str, result: dict) -> None:
        new_auc = float(result["metrics"].get("auc") or 0.0)
        from sentinel.storage.supabase_client import supabase

        async def _current():
            client = await supabase._ensure()
            return await client.table("models").select("id,metrics").eq(
                "tenant_id", tenant_id
            ).eq("active", True).limit(1).execute()

        response = await supabase._retry(_current)
        current = response.data or []
        if current:
            old_auc = float((current[0].get("metrics") or {}).get("auc") or 0.0)
            if new_auc < old_auc + self.min_auc_delta:
                logger.info("tenant %s: model not activated (auc %.4f <= %.4f)", tenant_id, new_auc, old_auc + self.min_auc_delta)
                return

        # The database partial unique index guarantees one active model per tenant.
        # Keep the swap in one async operation; if the activation fails, the old
        # model remains available until the caller retries.
        async def _activate():
            client = await supabase._ensure()
            await client.table("models").update({"active": False}).eq(
                "tenant_id", tenant_id
            ).eq("active", True).execute()
            return await client.table("models").update({"active": True}).eq(
                "tenant_id", tenant_id
            ).eq("version", result["version"]).execute()

        await supabase._retry(_activate)
        from sentinel.ml.runtime import registry
        await registry.invalidate(tenant_id)
        logger.info("activated model v%s for tenant %s", result["version"], tenant_id)
