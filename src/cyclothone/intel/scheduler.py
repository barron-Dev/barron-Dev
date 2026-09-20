from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import socket
import ssl
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from urllib.parse import urlparse

from cyclothone.storage.supabase_client import supabase

logger = logging.getLogger(__name__)


class ThreatIntelScheduler:
    INTERVAL_SECONDS = 900
    STARTUP_DELAY_SECONDS = 20
    MAX_BYTES = 5 * 1024 * 1024
    MAX_INDICATORS = 5000

    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._loop(), name="cyclothone-threat-intel")

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
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=self.STARTUP_DELAY_SECONDS)
            return
        except asyncio.TimeoutError:
            pass
        while not self._stop.is_set():
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("threat intelligence cycle failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.INTERVAL_SECONDS)
            except asyncio.TimeoutError:
                pass

    async def run_once(self) -> None:
        feeds = await self._feeds()
        for feed in feeds:
            try:
                indicators = await asyncio.to_thread(self._pull, feed)
                ingested = await self._ingest(feed, indicators)
                await self._mark(feed["id"], "ok")
                logger.info("intel feed=%s ingested=%d", feed["id"], ingested)
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._mark(feed["id"], "failed")
                logger.exception("intel feed failed: %s", feed["id"])

        await self._correlate_recent_events()

    async def _feeds(self) -> list[dict]:
        async def _do():
            return await (await supabase._ensure()).table("intel_feeds").select(
                "id,tenant_id,name,kind,endpoint,api_key_ref,enabled,last_pull_at,last_status"
            ).eq("enabled", True).execute()
        return list((await supabase._retry(_do, attempts=2)).data or [])

    def _pull(self, feed: dict) -> list[dict]:
        endpoint = str(feed.get("endpoint") or "").strip()
        parsed = urlparse(endpoint)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("intel_feed_requires_https")

        host = parsed.hostname
        port = parsed.port or 443
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        if not addresses:
            raise ValueError("intel_feed_dns_failed")
        for address in {item[4][0] for item in addresses}:
            ip = ipaddress.ip_address(address)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
                raise ValueError("intel_feed_private_or_reserved_address")

        headers = {"Accept": "application/json, application/stix+json, application/json;version=2.1"}
        ref = str(feed.get("api_key_ref") or "").strip()
        if ref:
            env_name = "CYCLOTHONE_INTEL_SECRET_" + "".join(ch if ch.isalnum() else "_" for ch in ref.upper())
            secret = os.getenv(env_name, "").strip()
            if secret:
                headers["Authorization"] = f"Bearer {secret}"

        request = urllib.request.Request(endpoint, headers=headers, method="GET")
        context = ssl.create_default_context()
        opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
        with opener.open(request, timeout=20, context=context) as response:
            if response.status != 200:
                raise ValueError(f"intel_feed_http_{response.status}")
            body = response.read(self.MAX_BYTES + 1)
        if len(body) > self.MAX_BYTES:
            raise ValueError("intel_feed_response_too_large")
        payload = json.loads(body.decode("utf-8"))
        return self._normalize(payload)

    def _normalize(self, payload: object) -> list[dict]:
        objects = payload.get("objects", []) if isinstance(payload, dict) and isinstance(payload.get("objects"), list) else payload
        if isinstance(objects, dict):
            objects = objects.get("indicators", [])
        if not isinstance(objects, list):
            raise ValueError("unsupported_intel_feed_payload")

        out: list[dict] = []
        for item in objects[: self.MAX_INDICATORS]:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "indicator":
                pattern = str(item.get("pattern") or "")
                value = self._extract_stix_value(pattern)
                if not value:
                    continue
                ioc_type = self._stix_type(pattern)
                out.append({"ioc_type": ioc_type, "value": value, "severity": "medium", "confidence": float(item.get("confidence") or 50) / 100.0, "context": item})
                continue
            value = str(item.get("value") or item.get("indicator") or "").strip()
            ioc_type = str(item.get("ioc_type") or item.get("type") or "unknown").lower()
            if value:
                out.append({"ioc_type": ioc_type, "value": value[:2048], "severity": str(item.get("severity") or "medium").lower(), "confidence": max(0.0, min(1.0, float(item.get("confidence") or 0.5))), "context": item})
        return out

    @staticmethod
    def _extract_stix_value(pattern: str) -> str | None:
        if " = " not in pattern:
            return None
        value = pattern.rsplit(" = ", 1)[-1].strip()
        if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
            return value[1:-1]
        return value or None

    @staticmethod
    def _stix_type(pattern: str) -> str:
        head = pattern.split("[", 1)[0].strip().lower()
        return {"file:hashes": "sha256", "domain-name:name": "domain", "ipv4-addr:value": "ipv4", "ipv6-addr:value": "ipv6", "url:value": "url", "email-addr:value": "email"}.get(head, head.replace(":", "_")[:64])

    async def _ingest(self, feed: dict, indicators: list[dict]) -> int:
        if not indicators:
            return 0
        rows = []
        for indicator in indicators:
            rows.append({
                "tenant_id": feed["tenant_id"],
                "ioc_type": indicator["ioc_type"],
                "value": indicator["value"],
                "severity": indicator["severity"] if indicator["severity"] in {"low","medium","high","critical"} else "medium",
                "confidence": indicator["confidence"],
                "source": f"feed:{feed['id']}",
                "tags": [feed["kind"]],
                "context": indicator["context"],
                "first_seen": datetime.now(UTC).isoformat(),
                "last_seen": datetime.now(UTC).isoformat(),
            })
        async def _do():
            return await (await supabase._ensure()).table("indicators").upsert(rows, on_conflict="tenant_id,ioc_type,value").execute()
        result = await supabase._retry(_do, attempts=2)
        return len(result.data or [])

    async def _mark(self, feed_id: str, status: str) -> None:
        async def _do():
            return await (await supabase._ensure()).table("intel_feeds").update({
                "last_pull_at": datetime.now(UTC).isoformat(),
                "last_status": status,
            }).eq("id", feed_id).execute()
        await supabase._retry(_do, attempts=2)

    async def _correlate_recent_events(self) -> None:
        async def _events():
            return await (await supabase._ensure()).table("events").select("id,tenant_id,device_id,event_type,ts,payload").gte(
                "ts", (datetime.now(UTC).timestamp() - 900)
            ).limit(1000).execute()
        # The event timestamp column is timestamptz; use an ISO bound after fetching the clock once.
        now = datetime.now(UTC)
        async def _events2():
            return await (await supabase._ensure()).table("events").select("id,tenant_id,device_id,event_type,ts,payload").gte(
                "ts", (now.timestamp() - 900)
            ).limit(1000).execute()
        events = (await supabase._retry(_events2, attempts=2)).data or []
        for event in events:
            haystack = json.dumps(event.get("payload") or {}, sort_keys=True).lower()
            if not haystack:
                continue
            async def _find():
                return await (await supabase._ensure()).table("indicators").select(
                    "id,ioc_type,value,severity,confidence,source"
                ).eq("tenant_id", event["tenant_id"]).execute()
            indicators = (await supabase._retry(_find, attempts=1)).data or []
            for indicator in indicators[:5000]:
                value = str(indicator.get("value") or "").lower()
                if len(value) < 3 or value not in haystack:
                    continue
                async def _existing():
                    return await (await supabase._ensure()).table("detections").select("id").eq("tenant_id", event["tenant_id"]).eq("event_id", event["id"]).contains("evidence", {"indicator_id": indicator["id"]}).limit(1).execute()
                if (await supabase._retry(_existing, attempts=1)).data:
                    continue
                score = max(0.0, min(1.0, float(indicator.get("confidence") or 0.5)))
                verdict = "malicious" if indicator.get("severity") in {"critical", "high"} else "suspicious"
                evidence = {"indicator_id": indicator["id"], "ioc_type": indicator["ioc_type"], "value": value, "source": indicator.get("source"), "event_type": event.get("event_type")}
                async def _insert():
                    return await (await supabase._ensure()).table("detections").insert({
                        "tenant_id": event["tenant_id"], "device_id": event.get("device_id"), "event_id": event["id"],
                        "detector": "threat_intel", "score": score, "verdict": verdict,
                        "reasons": ["threat_intelligence_match"], "evidence": evidence,
                    }).execute()
                await supabase._retry(_insert, attempts=2)
