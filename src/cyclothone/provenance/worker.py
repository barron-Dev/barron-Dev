from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
import tempfile
from pathlib import Path
from typing import Any

from cyclothone.provenance.engine import PermanentProvenanceError, verify_and_persist_media
from cyclothone.storage.supabase_client import supabase

logger = logging.getLogger("cyclothone.provenance.worker")
BUCKET = "cyclothone-provenance-staging"
POLL_SECONDS = float(os.getenv("CYCLOTHONE_PROVENANCE_WORKER_POLL_SECONDS", "2"))


class MediaProvenanceWorker:
    def __init__(self) -> None:
        self._stop = asyncio.Event()

    async def run_once(self) -> bool:
        claimed = await supabase.rpc("claim_media_provenance_job", {})
        rows = claimed if isinstance(claimed, list) else ([claimed] if isinstance(claimed, dict) else [])
        if not rows:
            return False

        job = rows[0]
        job_id = str(job["id"])
        attempt = int(job["attempts"])
        object_path = str(job["object_path"])
        client = await supabase._ensure()
        temp_path: str | None = None

        try:
            media = await client.storage.from_(BUCKET).download(object_path)
            if not isinstance(media, (bytes, bytearray)):
                raise RuntimeError("storage_download_invalid")
            suffix = Path(str(job.get("original_filename") or "")).suffix[:16]
            with tempfile.NamedTemporaryFile(prefix="cyclothone-provenance-worker-", suffix=suffix, delete=False) as tmp:
                temp_path = tmp.name
                tmp.write(media)

            result = await verify_and_persist_media(str(job["tenant_id"]), temp_path, job_id)
            completed = await supabase.update(
                "media_provenance_jobs",
                {
                    "status": "succeeded",
                    "receipt_id": result["receipt_id"],
                    "validation_state": result["validation_state"],
                    "result_json": result,
                    "failure_code": None,
                    "lease_expires_at": None,
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                },
                id=job_id,
                attempts=attempt,
                status="processing",
            )
            if completed is None:
                logger.warning("stale provenance worker completion rejected job_id=%s", job_id)
                return True
            await client.storage.from_(BUCKET).remove([object_path])
            logger.info("media provenance job completed job_id=%s state=%s", job_id, result["validation_state"])
        except Exception as exc:
            permanent = isinstance(exc, PermanentProvenanceError)
            exhausted = attempt >= int(job.get("max_attempts") or 3)
            terminal = permanent or exhausted
            update = {
                "status": "failed" if terminal else "queued",
                "failure_code": str(exc)[:80] if isinstance(exc, PermanentProvenanceError) else type(exc).__name__,
                "lease_expires_at": None,
                "available_at": (
                    datetime.now(timezone.utc).isoformat()
                    if terminal else (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat()
                ),
                "completed_at": datetime.now(timezone.utc).isoformat() if terminal else None,
            }
            failed = await supabase.update(
                "media_provenance_jobs", update,
                id=job_id, attempts=attempt, status="processing",
            )
            if failed is not None and terminal:
                try:
                    await client.storage.from_(BUCKET).remove([object_path])
                except Exception:
                    logger.warning("provenance staging cleanup failed job_id=%s", job_id)
            logger.error(
                "media provenance job failed job_id=%s attempt=%s error_type=%s terminal=%s",
                job_id, attempt, type(exc).__name__, terminal,
            )
        finally:
            if temp_path:
                Path(temp_path).unlink(missing_ok=True)
        return True

    async def run(self) -> None:
        logger.info("media provenance worker started")
        while not self._stop.is_set():
            try:
                claimed = await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("media provenance worker poll failed error_type=%s", type(exc).__name__)
                claimed = False
            if not claimed:
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=POLL_SECONDS)
                except asyncio.TimeoutError:
                    pass
        logger.info("media provenance worker stopped")

    async def stop(self) -> None:
        self._stop.set()


async def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    worker = MediaProvenanceWorker()
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
