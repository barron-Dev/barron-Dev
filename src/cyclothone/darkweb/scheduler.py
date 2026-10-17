from __future__ import annotations

import asyncio
import logging
import time
from urllib.parse import urlsplit
from datetime import UTC, datetime

from cyclothone.darkweb.matcher import DarkWebMatcher
from cyclothone.darkweb.native_onion import NativeOnionCrawler, configured_onion_seeds
from cyclothone.darkweb.pullers import PastePublicMonitor, TelegramPublicMonitor
from cyclothone.darkweb.telegram_config import (
    DEFAULT_PUBLIC_TELEGRAM_CHANNELS,  # noqa: F401 — compatibility export
    configured_telegram_channels,
)
from cyclothone.storage.supabase_client import supabase

logger = logging.getLogger(__name__)


def _configured_telegram_channels() -> list[str]:
    return configured_telegram_channels()


class DarkWebScheduler:
    GLOBAL_INTERVAL = 15 * 60
    DOMAIN_INTERVAL = 6 * 3600
    STARTUP_DELAY = 30

    def __init__(self) -> None:
        self.matcher = DarkWebMatcher()
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._last_domain = 0.0

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._loop(), name="cyclothone-darkweb")

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
        await asyncio.sleep(self.STARTUP_DELAY)
        while not self._stop.is_set():
            try:
                await self._global_tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("dark web global tick failed")
            if time.monotonic() - self._last_domain >= self.DOMAIN_INTERVAL:
                try:
                    await self._domain_tick()
                    self._last_domain = time.monotonic()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("dark web domain tick failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.GLOBAL_INTERVAL)
            except asyncio.TimeoutError:
                pass

    async def _global_tick(self) -> None:
        enabled = await self._enabled_sources()
        # Ransomwatch is archived and must never be represented as a fresh source check.
        if "ransomwatch" in enabled:
            await self._mark_source("ransomwatch", "historical_only_archived_feed", pulled=False)
        paste = PastePublicMonitor()
        if paste.SOURCE in enabled:
            await self._run_pull(paste.SOURCE, paste.pull)
        channels = _configured_telegram_channels()
        if channels and "telegram_public" in enabled:
            monitor = TelegramPublicMonitor(channels)
            await self._run_pull(monitor.SOURCE, monitor.pull)
        elif "telegram_public" in enabled:
            await self._mark_source("telegram_public", "unavailable_missing_channel", pulled=False)

    async def _onion_seed_urls(self) -> tuple[list[str], dict[str, str], dict[str, str]]:
        seeds = configured_onion_seeds()
        origins = {seed: "configured" for seed in seeds}
        discovered_from: dict[str, str] = {}
        try:
            async def _do():
                client = await supabase._ensure()
                return await (
                    client.table("dw_onion_seeds")
                    .select("url,status,seed_origin,discovered_from,last_checked")
                    .in_("status", ["checked", "failed"])
                    .order("last_checked", desc=True)
                    .limit(50)
                    .execute()
                )
            rows = (await supabase._retry(_do, attempts=1)).data or []
            for row in rows:
                url = str(row.get("url") or "").strip()
                if url and url not in origins and len(seeds) < 50:
                    seeds.append(url)
                    origins[url] = "discovered" if row.get("seed_origin") == "discovered" else "configured"
                    if row.get("discovered_from"):
                        discovered_from[url] = str(row["discovered_from"])
        except Exception:
            logger.warning("native onion seed registry unavailable", exc_info=True)
        return seeds[:50], origins, discovered_from

    async def _domain_tick(self) -> None:
        domains = await self._tenant_domains()
        enabled = await self._enabled_sources()
        seeds, seed_origins, seed_discovered_from = await self._onion_seed_urls()
        if "native_onion" not in enabled:
            return
        if not seeds:
            await self._mark_source("native_onion", "unavailable_missing_onion_seeds", pulled=False)
            return
        for domain in domains:
            crawler = NativeOnionCrawler(
                seeds=seeds,
                seed_origins=seed_origins,
                discovered_from=seed_discovered_from,
            )
            await self._run_pull(
                crawler.SOURCE,
                lambda c=crawler, d=domain: c.pull("domain", d),
                monitor=crawler,
            )

    async def _run_pull(self, source_id: str, pull, *, monitor=None) -> None:
        started = time.monotonic()
        try:
            findings = await pull()
            monitor = monitor or getattr(pull, "__self__", None)
            if source_id == "native_onion" and monitor is not None:
                await self._persist_onion_seed_state(monitor)
            result = await self._ingest(findings)
            channel_status = getattr(monitor, "channel_status", {})
            failed_channels = [channel for channel, state in channel_status.items() if state != "checked"]
            source_status = "degraded" if result["errors"] or failed_channels else "ok"
            for channel, state in channel_status.items():
                logger.info("dark web source=%s channel=%s state=%s", source_id, channel, state)
            await self._mark_source(source_id, source_status)
            logger.info(
                "dark web source=%s completed findings=%d matched=%d alerts=%d errors=%d channels_checked=%d channels_failed=%d duration_ms=%d",
                source_id, len(findings), result["matched"], result["alerts"], result["errors"],
                sum(state == "checked" for state in channel_status.values()), len(failed_channels),
                int((time.monotonic() - started) * 1000),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            await self._mark_source(source_id, "failed")
            logger.exception("dark web source failed: %s", source_id)

    async def _ingest(self, findings: list) -> dict[str, int]:
        matched = alerts = errors = 0
        for finding in findings[:2000]:
            if self._stop.is_set():
                return {"matched": matched, "alerts": alerts, "errors": errors}
            result = await self.matcher.process({
                "source_id": finding.source_id, "kind": finding.kind,
                "matched_value": finding.matched_value, "context": finding.context,
                "severity": finding.severity, "source_url": finding.source_url,
                "metadata": finding.metadata,
            })
            matched += int(result.get("matched", 0))
            alerts += int(result.get("alerts", 0))
            errors += int(result.get("errors", 0))
        return {"matched": matched, "alerts": alerts, "errors": errors}

    async def _persist_onion_seed_state(self, crawler: NativeOnionCrawler) -> None:
        rows = []
        for url, state in crawler.seed_status.items():
            parsed = urlsplit(url)
            row = {
                "url": url,
                "hostname": (parsed.hostname or "").lower(),
                "seed_origin": crawler.seed_origin.get(url, "configured"),
                "discovered_from": crawler.discovered_from.get(url),
                "status": state if state in {"checked", "failed", "disabled"} else "candidate",
                "last_status": state,
                "last_checked": datetime.now(UTC).isoformat() if state in {"checked", "failed"} else None,
            }
            digest = crawler.seed_content_hash.get(url)
            if digest:
                row["last_response_sha256"] = digest
            rows.append(row)
        if not rows:
            return

        async def _do():
            client = await supabase._ensure()
            return await client.table("dw_onion_seeds").upsert(rows, on_conflict="url").execute()

        await supabase._retry(_do, attempts=2)

    async def _enabled_sources(self) -> set[str]:
        async def _do():
            return await (await supabase._ensure()).table("dw_sources").select("id").eq("enabled", True).execute()
        try:
            rows = (await supabase._retry(_do, attempts=1)).data or []
            return {str(row["id"]) for row in rows if row.get("id")}
        except Exception:
            logger.warning("dark web source configuration unavailable; failing closed", exc_info=True)
            return set()

    async def _mark_source(self, source_id: str, status: str, *, pulled: bool = True) -> None:
        update = {"last_status": status}
        if pulled:
            update["last_pull_at"] = datetime.now(UTC).isoformat()

        async def _do():
            return await (await supabase._ensure()).table("dw_sources").update(
                update
            ).eq("id", source_id).execute()
        try:
            await supabase._retry(_do, attempts=1)
        except Exception:
            logger.warning("unable to persist dark web source health: %s", source_id, exc_info=True)

    async def _tenant_domains(self) -> list[str]:
        async def _do():
            return await (await supabase._ensure()).table("dw_watchlist").select("value").eq("kind", "domain").execute()
        try:
            rows = (await supabase._retry(_do, attempts=1)).data or []
            return sorted({str(row["value"]).strip().lower() for row in rows if row.get("value")})
        except Exception:
            logger.debug("dark web domain watchlist unavailable", exc_info=True)
            return []
