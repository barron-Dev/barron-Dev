from __future__ import annotations

import asyncio
import logging

from cyclothone.storage.supabase_client import supabase

logger = logging.getLogger(__name__)


class TrustReevaluationScheduler:
    """Service-role worker for authoritative trust re-evaluation jobs.

    The worker never creates or activates certificates. It only recomputes the
    trust state for subjects whose authoritative trust inputs changed.
    """

    POLL_INTERVAL_SECONDS = 2
    CLAIM_LIMIT = 25

    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

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
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                claimed = await supabase.rpc(
                    "trust_claim_re_evaluation",
                    {"p_limit": self.CLAIM_LIMIT},
                )
                jobs = claimed if isinstance(claimed, list) else [claimed] if claimed else []

                if not jobs:
                    await self._sleep()
                    continue

                for job in jobs:
                    await self._process(job)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("trust re-evaluation worker iteration failed")
                await self._sleep()

    async def _process(self, job: dict) -> None:
        queue_id = job.get("id")
        subject_id = job.get("subject_id")
        if not queue_id or not subject_id:
            logger.error("invalid trust re-evaluation job: %r", job)
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
                logger.exception(
                    "failed to settle trust re-evaluation queue=%s", queue_id
                )

    async def _sleep(self) -> None:
        try:
            await asyncio.wait_for(
                self._stop.wait(), timeout=self.POLL_INTERVAL_SECONDS
            )
        except asyncio.TimeoutError:
            pass
