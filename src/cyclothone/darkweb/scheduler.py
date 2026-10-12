from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import UTC, datetime

from cyclothone.darkweb.matcher import DarkWebMatcher
from cyclothone.darkweb.pullers import (
    BlueskyPublicMonitor,
    HackerNewsPublicMonitor,
    LemmyPublicMonitor,
    PastePublicMonitor,
    RedditPublicMonitor,
    TelegramPublicMonitor,
    YouTubePublicMonitor,
)
from cyclothone.darkweb.telegram_config import (
    DEFAULT_PUBLIC_TELEGRAM_CHANNELS,  # noqa: F401 — compatibility export
    configured_telegram_channels,
)
from cyclothone.darkweb.tiktok import TikTokCommercialContentMonitor
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
        domains = await self._tenant_domains()
        tiktok_credentials = bool(
            (os.getenv("CYCLOTHONE_TIKTOK_CLIENT_KEY") or "").strip()
            and (os.getenv("CYCLOTHONE_TIKTOK_CLIENT_SECRET") or "").strip()
        )
        if "tiktok_commercial" in enabled and not tiktok_credentials:
            await self._mark_source("tiktok_commercial", "unavailable_missing_api_credentials", pulled=False)
        elif "tiktok_commercial" in enabled:
            targets = await self._tenant_tiktok_targets()
            if targets:
                monitor = TikTokCommercialContentMonitor()
                await self._run_pull("tiktok_commercial", lambda m=monitor, t=targets: m.pull_targets(t))
            else:
                await self._mark_source("tiktok_commercial", "unavailable_missing_watch_targets", pulled=False)
        youtube_api_key = (os.getenv("CYCLOTHONE_YOUTUBE_API_KEY") or "").strip()
        if domains and "youtube_public" in enabled and youtube_api_key:
            monitor = YouTubePublicMonitor(youtube_api_key)
            await self._run_pull("youtube_public", lambda m=monitor, d=domains: m.pull_domains(d))
        elif "youtube_public" in enabled and not youtube_api_key:
            await self._mark_source("youtube_public", "unavailable_missing_api_key", pulled=False)
        elif "youtube_public" in enabled:
            await self._mark_source("youtube_public", "unavailable_missing_watch_targets", pulled=False)
        if domains and "bluesky_public" in enabled:
            monitor = BlueskyPublicMonitor()
            await self._run_pull("bluesky_public", lambda m=monitor, d=domains: m.pull_domains(d))
        elif "bluesky_public" in enabled:
            await self._mark_source("bluesky_public", "unavailable_missing_watch_targets", pulled=False)
        reddit_credentials = bool(
            (os.getenv("CYCLOTHONE_REDDIT_CLIENT_ID") or "").strip()
            and (os.getenv("CYCLOTHONE_REDDIT_CLIENT_SECRET") or "").strip()
        )
        if domains and "reddit_public" in enabled and reddit_credentials:
            monitor = RedditPublicMonitor()
            await self._run_pull("reddit_public", lambda m=monitor, d=domains: m.pull_domains(d))
        elif "reddit_public" in enabled and not reddit_credentials:
            await self._mark_source("reddit_public", "unavailable_missing_api_credentials", pulled=False)
        elif "reddit_public" in enabled:
            await self._mark_source("reddit_public", "unavailable_missing_watch_targets", pulled=False)
        if domains and "hackernews_public" in enabled:
            monitor = HackerNewsPublicMonitor()
            await self._run_pull("hackernews_public", lambda m=monitor, d=domains: m.pull_domains(d))
        elif "hackernews_public" in enabled:
            await self._mark_source("hackernews_public", "unavailable_missing_watch_targets", pulled=False)
        if domains and "lemmy_public" in enabled:
            monitor = LemmyPublicMonitor()
            await self._run_pull("lemmy_public", lambda m=monitor, d=domains: m.pull_domains(d))
        elif "lemmy_public" in enabled:
            await self._mark_source("lemmy_public", "unavailable_missing_watch_targets", pulled=False)

    async def _domain_tick(self) -> None:
        domains = await self._tenant_domains()
        enabled = await self._enabled_sources()
        if "github_code" in enabled:
            # GitHub Code Search currently returns 403 in production. Do not retry it
            # on every domain; expose the restriction honestly while public sources run.
            await self._mark_source("github_code", "unavailable_provider_403", pulled=False)

    async def _run_pull(self, source_id: str, pull) -> None:
        started = time.monotonic()
        try:
            findings = await pull()
            result = await self._ingest(findings)
            monitor = getattr(pull, "__self__", None)
            channel_status = getattr(monitor, "channel_status", {})
            failed_channels = [channel for channel, state in channel_status.items() if state != "checked"]
            source_status = "degraded" if result["errors"] or failed_channels or bool(getattr(monitor, "coverage_partial", False)) else "ok"
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


    async def _tenant_tiktok_targets(self) -> list[tuple[str, str]]:
        async def _do():
            return await (await supabase._ensure()).table("dw_watchlist").select("kind,value").in_(
                "kind", ["domain", "company_name", "username"]
            ).execute()
        try:
            rows = (await supabase._retry(_do, attempts=1)).data or []
            unique = {
                (str(row.get("kind") or "").strip().lower(), str(row.get("value") or "").strip().lower())
                for row in rows
                if row.get("kind") and row.get("value")
            }
            targets = sorted(unique)
            return targets[:20]
        except Exception:
            logger.debug("TikTok commercial watchlist unavailable", exc_info=True)
            return []

    async def _tenant_domains(self) -> list[str]:
        async def _do():
            return await (await supabase._ensure()).table("dw_watchlist").select("value").eq("kind", "domain").execute()
        try:
            rows = (await supabase._retry(_do, attempts=1)).data or []
            return sorted({str(row["value"]).strip().lower() for row in rows if row.get("value")})
        except Exception:
            logger.debug("dark web domain watchlist unavailable", exc_info=True)
            return []
