from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from datetime import UTC, datetime
from urllib.parse import urlsplit

from cyclothone.darkweb.matcher import DarkWebMatcher
from cyclothone.darkweb.pullers import GitHubCodeMonitor, HIBPPuller, PastePublicMonitor, TelegramPublicMonitor
from cyclothone.storage.supabase_client import supabase

logger = logging.getLogger(__name__)

# Public handles supplied for Cyclothone's existing Telegram ingestion path.
# Availability is deliberately not asserted here; every channel is checked at runtime.
DEFAULT_PUBLIC_TELEGRAM_CHANNELS = (
    "gladdos69_official",
    "arvin_club",
    "cveNotify",
    "bugatti_cloud",
    "joker_reborn",
    "ObserverCloud",
    "darkstormteambackup2",
    "snatch_info",
    "bl00dy_Ransomware_Gang",
    "Stormous",
    "Openbullet",
    "Forum",
    "AresLoader",
)


def _configured_telegram_channels() -> list[str]:
    """Resolve configured/default public usernames and reject invite/private URLs."""
    configured = os.getenv("CYCLOTHONE_DW_TELEGRAM_CHANNELS")
    if configured is None:
        configured = os.getenv("SENTINEL_DW_TELEGRAM_CHANNELS")
    raw_channels = (
        list(DEFAULT_PUBLIC_TELEGRAM_CHANNELS)
        if configured is None
        else configured.split(",")
    )

    channels: list[str] = []
    seen: set[str] = set()
    for raw in raw_channels:
        value = raw.strip()
        if not value:
            continue
        if "://" in value or value.lower().startswith(("t.me/", "telegram.me/")):
            parsed = urlsplit(value if "://" in value else f"https://{value}")
            if (parsed.hostname or "").lower() not in {"t.me", "www.t.me", "telegram.me", "www.telegram.me"}:
                continue
            parts = [part for part in parsed.path.split("/") if part]
            if parts and parts[0].lower() == "s":
                parts = parts[1:]
            # Invite links and non-channel paths are intentionally excluded.
            if len(parts) != 1 or parts[0].startswith("+") or parts[0].lower() == "joinchat":
                continue
            value = parts[0]
        else:
            value = value.lstrip("@")
        if not re.fullmatch(r"[A-Za-z0-9_]{5,32}", value):
            continue
        key = value.lower()
        if key not in seen:
            seen.add(key)
            channels.append(value)
    return channels


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

    async def _domain_tick(self) -> None:
        domains = await self._tenant_domains()
        hibp_key = (os.getenv("CYCLOTHONE_HIBP_KEY") or os.getenv("SENTINEL_HIBP_KEY") or "").strip()
        github_token = (os.getenv("CYCLOTHONE_GITHUB_TOKEN") or os.getenv("SENTINEL_GITHUB_TOKEN") or "").strip()
        enabled = await self._enabled_sources()
        for domain in domains:
            if hibp_key and "hibp" in enabled:
                puller = HIBPPuller(hibp_key)
                await self._run_pull(puller.SOURCE, lambda p=puller, d=domain: p.pull_domain(d))
            if github_token and "github_code" in enabled:
                monitor = GitHubCodeMonitor(github_token)
                await self._run_pull(monitor.SOURCE, lambda m=monitor, d=domain: m.pull_domain(d))

    async def _run_pull(self, source_id: str, pull) -> None:
        started = time.monotonic()
        try:
            findings = await pull()
            result = await self._ingest(findings)
            source_status = "degraded" if result["errors"] else "ok"
            await self._mark_source(source_id, source_status)
            logger.info(
                "dark web source=%s completed findings=%d matched=%d alerts=%d errors=%d duration_ms=%d",
                source_id, len(findings), result["matched"], result["alerts"], result["errors"], int((time.monotonic() - started) * 1000),
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

    async def _tenant_domains(self) -> list[str]:
        async def _do():
            return await (await supabase._ensure()).table("dw_watchlist").select("value").eq("kind", "domain").execute()
        try:
            rows = (await supabase._retry(_do, attempts=1)).data or []
            return sorted({str(row["value"]).strip().lower() for row in rows if row.get("value")})
        except Exception:
            logger.debug("dark web domain watchlist unavailable", exc_info=True)
            return []
