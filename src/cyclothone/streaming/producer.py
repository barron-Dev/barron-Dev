from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

logger = logging.getLogger(__name__)

@dataclass(frozen=True, slots=True)
class EventEnvelope:
    event_id: str
    tenant_id: str
    region_code: str
    topic: str
    kind: str
    ts: str
    payload: dict[str, Any]
    trace_id: str | None = None
    parent_id: str | None = None
    headers: dict[str, str] = field(default_factory=dict)

class EventProducer:
    """Production Kafka/Redpanda producer. There is deliberately no in-process fallback."""
    MAX_PAYLOAD_BYTES = 1_048_576

    def __init__(self, bootstrap: str | None = None, compression: str = "zstd", linger_ms: int = 20) -> None:
        self.bootstrap = bootstrap or os.getenv("CYCLOTHONE_KAFKA_BOOTSTRAP")
        if not self.bootstrap:
            raise RuntimeError("CYCLOTHONE_KAFKA_BOOTSTRAP is required")
        self.compression = compression
        self.linger_ms = linger_ms
        self._producer = None
        self._lock = asyncio.Lock()

    async def _ensure(self):
        if self._producer is not None:
            return self._producer
        async with self._lock:
            if self._producer is not None:
                return self._producer
            from aiokafka import AIOKafkaProducer
            kwargs: dict[str, Any] = dict(
                bootstrap_servers=self.bootstrap,
                compression_type=self.compression,
                linger_ms=self.linger_ms,
                acks="all",
                enable_idempotence=True,
                max_batch_size=1_048_576,
                request_timeout_ms=30_000,
                retry_backoff_ms=250,
            )
            protocol = os.getenv("CYCLOTHONE_KAFKA_SECURITY_PROTOCOL")
            if protocol:
                kwargs["security_protocol"] = protocol
            mechanism = os.getenv("CYCLOTHONE_KAFKA_SASL_MECHANISM")
            if mechanism:
                kwargs["sasl_mechanism"] = mechanism
            username = os.getenv("CYCLOTHONE_KAFKA_SASL_USER")
            password = os.getenv("CYCLOTHONE_KAFKA_SASL_PASSWORD")
            if username is not None or password is not None:
                if not username or not password:
                    raise RuntimeError("Kafka SASL user and password must be supplied together")
                kwargs["sasl_plain_username"] = username
                kwargs["sasl_plain_password"] = password
            self._producer = AIOKafkaProducer(**kwargs)
            await self._producer.start()
            logger.info("Redpanda producer connected")
            return self._producer

    async def publish(self, tenant_id: UUID, topic: str, kind: str, payload: dict[str, Any], correlation_key: str | None = None, trace_id: str | None = None, parent_id: str | None = None) -> str:
        if not topic or topic.startswith("_") or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for c in topic):
            raise ValueError("invalid topic")
        if not kind or len(kind) > 128:
            raise ValueError("invalid event kind")
        region = os.getenv("CYCLOTHONE_REGION")
        if not region:
            raise RuntimeError("CYCLOTHONE_REGION is required")
        envelope = EventEnvelope(str(uuid4()), str(tenant_id), region, topic, kind, datetime.now(timezone.utc).isoformat(), payload, trace_id, parent_id)
        value = self._serialize(envelope)
        if len(value) > self.MAX_PAYLOAD_BYTES:
            raise ValueError("event exceeds maximum payload size")
        key = f"{tenant_id}:{correlation_key or envelope.event_id}".encode("utf-8")
        producer = await self._ensure()
        await producer.send_and_wait(topic, value=value, key=key)
        return envelope.event_id

    async def close(self) -> None:
        if self._producer is not None:
            await self._producer.stop()
            self._producer = None

    @staticmethod
    def _serialize(env: EventEnvelope) -> bytes:
        return json.dumps({"event_id":env.event_id,"tenant_id":env.tenant_id,"region_code":env.region_code,"topic":env.topic,"kind":env.kind,"ts":env.ts,"trace_id":env.trace_id,"parent_id":env.parent_id,"payload":env.payload,"headers":env.headers},separators=(",",":"),ensure_ascii=False,allow_nan=False,default=str).encode("utf-8")
