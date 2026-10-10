from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import UTC, datetime

from cyclothone.darkweb.pullers import Finding
from cyclothone.storage.supabase_client import supabase
from cyclothone.streaming.change_detection import build_change_event

logger = logging.getLogger(__name__)


class ChangeEventPipeline:
    """Durable database outbox with an optional Kafka Streams hand-off.

    The outbox is the source of retry truth. Kafka delivery is at-least-once;
    consumers must deduplicate by event_id. Missing Kafka configuration leaves
    events durably queued instead of silently discarding them.
    """

    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._producer = None
        self._logged_disabled = False

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._dispatch_loop(), name="cyclothone-change-events")

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        if self._producer is not None:
            try:
                await self._producer.stop()
            finally:
                self._producer = None

    async def enqueue_finding(self, finding: Finding) -> str:
        event = build_change_event(finding)
        # This RPC is idempotent on event_id and is installed by the matching
        # migration. A missing migration is surfaced to the scheduler as degraded
        # coverage; we do not fall back to in-memory "success".
        result = await supabase.rpc("record_dw_change_event", {"p_event": event})
        return str(result or event["event_id"])

    async def _get_producer(self):
        if self._producer is not None:
            return self._producer
        bootstrap = (os.getenv("CYCLOTHONE_KAFKA_BOOTSTRAP_SERVERS") or "").strip()
        if not bootstrap:
            return None
        from aiokafka import AIOKafkaProducer

        self._producer = AIOKafkaProducer(
            bootstrap_servers=[item.strip() for item in bootstrap.split(",") if item.strip()],
            client_id="cyclothone-change-event-publisher",
            value_serializer=lambda value: json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8"),
        )
        await self._producer.start()
        return self._producer

    async def _dispatch_loop(self) -> None:
        while not self._stop.is_set():
            try:
                await self.dispatch_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.warning("change-event dispatch cycle failed", exc_info=True)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                pass

    async def dispatch_once(self) -> int:
        producer = await self._get_producer()
        if producer is None:
            if not self._logged_disabled:
                logger.info("change-event outbox active; Kafka dispatch awaits CYCLOTHONE_KAFKA_BOOTSTRAP_SERVERS")
                self._logged_disabled = True
            return 0
        topic = (os.getenv("CYCLOTHONE_KAFKA_CHANGE_TOPIC") or "cyclothone.change-events.v1").strip()
        client = await supabase._ensure()
        response = await (
            client.table("dw_change_events")
            .select("event_id,payload,publish_attempts")
            .is_("published_at", "null")
            .order("collected_at")
            .limit(100)
            .execute()
        )
        rows = response.data or []
        sent = 0
        for row in rows:
            if self._stop.is_set():
                break
            event_id = str(row["event_id"])
            attempts = int(row.get("publish_attempts") or 0) + 1
            try:
                await producer.send_and_wait(
                    topic,
                    row["payload"],
                    key=event_id.encode("utf-8"),
                )
                await (
                    client.table("dw_change_events")
                    .update({
                        "published_at": datetime.now(UTC).isoformat(),
                        "publish_attempts": attempts,
                        "last_publish_error": None,
                    })
                    .eq("event_id", event_id)
                    .is_("published_at", "null")
                    .execute()
                )
                sent += 1
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Store a bounded error code only; provider/network exception text
                # can contain hostnames or credentials and is intentionally omitted.
                await (
                    client.table("dw_change_events")
                    .update({
                        "publish_attempts": attempts,
                        "last_publish_error": type(exc).__name__[:80],
                    })
                    .eq("event_id", event_id)
                    .is_("published_at", "null")
                    .execute()
                )
                logger.warning("change event remains queued event_id=%s error=%s", event_id, type(exc).__name__)
        return sent
