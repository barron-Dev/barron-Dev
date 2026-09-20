from __future__ import annotations

import asyncio
import logging

from cyclothone.storage.supabase_client import supabase

logger = logging.getLogger(__name__)


class TrustReevaluationScheduler:
    """Service-role worker for authoritative trust re-evaluation jobs."""

    POLL_INTERVAL_SECONDS = 2
    HEARTBEAT_INTERVAL_SECONDS = 15
    CLAIM_LIMIT = 25

    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._last_heartbeat = 0.0

    def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(
            self._loop(), name="cyclothone-trust-reevaluation"
        )

    async def stop(self) -> None:
        self._stop.set()
        task, self._task = self._task, None
        try:
            await self._heartbeat("STOPPING")
        except Exception:
            logger.exception("failed to record trust worker stopping heartbeat")
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def _loop(self) -> None:
        await self._heartbeat("STARTING")
        await self._heartbeat("RUNNING")
        loop = asyncio.get_running_loop()
        self._last_heartbeat = loop.time()

        while not self._stop.is_set():
            try:
                now = loop.time()
                if now - self._last_heartbeat >= self.HEARTBEAT_INTERVAL_SECONDS:
                    await self._heartbeat("RUNNING")
                    self._last_heartbeat = now

                claimed = await supabase.rpc(
                    "trust_claim_re_evaluation",
                    {"p_limit": self.CLAIM_LIMIT},
                )
                jobs = claimed if isinstance(claimed, list) else [claimed] if claimed else []

                for job in jobs:
                    await self._process(job)

                await self._sleep()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("trust re-evaluation worker iteration failed")
                try:
                    await self._heartbeat("ERROR", error_code="worker_iteration_failed")
                except Exception:
                    logger.exception("failed to record trust worker error heartbeat")
                await self._sleep()

    async def _process(self, job: dict) -> None:
        queue_id = job.get("id")
        subject_id = job.get("subject_id")
        if not queue_id or not subject_id:
            logger.error("invalid trust re-evaluation job")
            try:
                await self._heartbeat("ERROR", error_code="invalid_job")
            except Exception:
                logger.exception("failed to record invalid-job heartbeat")
            return

        try:
            result = await supabase.rpc(
                "trust_continuous_verify_subject",
                {"p_subject_id": subject_id},
            )
            await supabase.rpc(
                "trust_complete_re_evaluation",
                {
                    "p_queue_id": queue_id,
                    "p_success": True,
                    "p_result": result or {},
                },
            )
            try:
                await self._heartbeat("RUNNING")
            except Exception:
                logger.exception("failed to record trust worker success heartbeat")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception(
                "trust re-evaluation failed subject=%s queue=%s",
                subject_id,
                queue_id,
            )
            try:
                await supabase.rpc(
                    "trust_complete_re_evaluation",
                    {
                        "p_queue_id": queue_id,
                        "p_success": False,
                        "p_result": {"subject_id": subject_id},
                        "p_error": str(exc)[:2000],
                    },
                )
            except Exception:
                logger.exception("failed to settle trust re-evaluation queue")
            try:
                await self._heartbeat("ERROR", error_code="job_failed")
            except Exception:
                logger.exception("failed to record trust worker failure heartbeat")

    async def _heartbeat(self, status: str, *, error_code: str | None = None) -> None:
        await supabase.rpc(
            "trust_worker_heartbeat",
            {
                "p_worker_name": "trust-reevaluation",
                "p_status": status,
                "p_success": status == "RUNNING",
                "p_error_code": error_code,
                "p_metadata": {
                    "poll_interval_seconds": self.POLL_INTERVAL_SECONDS,
                    "heartbeat_interval_seconds": self.HEARTBEAT_INTERVAL_SECONDS,
                    "claim_limit": self.CLAIM_LIMIT,
                },
            },
        )

    async def _sleep(self) -> None:
        try:
            await asyncio.wait_for(
                self._stop.wait(), timeout=self.POLL_INTERVAL_SECONDS
            )
        except asyncio.TimeoutError:
            pass
