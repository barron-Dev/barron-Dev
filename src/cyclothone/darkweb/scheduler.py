from __future__ import annotations

import asyncio
import logging
import os
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


def _native_onion_monitoring_enabled() -> bool:
    """Fail closed: native onion crawling is opt-in at the runtime level."""
    return os.getenv("CYCLOTHONE_DW_NATIVE_ONION_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}


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
        if not _native_onion_monitoring_enabled():
            return [], {}, {}
        seeds = configured_onion_seeds()
        origins = {seed: "configured" for seed in seeds}
        discovered_from: dict[str, str] = {}
        try:
            async def _do():
                client = await supabase._ensure()
                return await (
                    client.table("dw_onion_seeds")
                    .select("url,status,seed_origin,discovered_from,last_checked,monitoring_enabled,retired_at")
                    .eq("monitoring_enabled", True)
                    .in_("status", ["active", "checked", "failed"])
                    .order("last_checked", desc=True)
                    .limit(50)
                    .execute()
                )
            rows = (await supabase._retry(_do, attempts=1)).data or []
            for row in rows:
                # DB registry entries are eligible only when explicitly enabled and not retired.
                if row.get("monitoring_enabled") is not True or row.get("retired_at") is not None:
                    continue
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
        if not _native_onion_monitoring_enabled():
            logger.info("native onion monitoring disabled by CYCLOTHONE_DW_NATIVE_ONION_ENABLED")
            return
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
            # A failed onion crawl still contains real per-seed attempt outcomes.
            # Persist them through the evidence RPC before marking the source failed.
            if source_id == "native_onion" and monitor is not None:
                try:
                    await self._persist_onion_seed_state(monitor)
                except Exception:
                    logger.exception("native onion probe evidence persistence failed")
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
        """Persist every real seed probe through the evidence RPC; never activate by upsert."""
        for url, state in crawler.seed_status.items():
            parsed = urlsplit(url)
            hostname = (parsed.hostname or "").lower()
            label = hostname.removesuffix(".onion")
            # The evidence RPC deliberately accepts only v3 onion hostnames.
            if not hostname.endswith(".onion") or len(label) != 56 or any(ch not in "abcdefghijklmnopqrstuvwxyz234567" for ch in label):
                logger.warning("native onion probe evidence skipped invalid v3 hostname")
                continue

            async def _lookup():
                client = await supabase._ensure()
                return await client.table("dw_onion_seeds").select("id,seed_type").eq("url", url).limit(1).execute()

            rows = (await supabase._retry(_lookup, attempts=1)).data or []
            if rows:
                seed = rows[0]
            else:
                candidate = {
                    "url": url,
                    "hostname": hostname,
                    "seed_origin": crawler.seed_origin.get(url, "discovered"),
                    "discovered_from": crawler.discovered_from.get(url),
                    "status": "candidate",
                    "last_status": "not_probed",
                    "seed_type": "candidate_onion_service",
                    "candidate_trust": "candidate",
                    "monitoring_enabled": False,
                    "requires_tor_probe": True,
                }

                async def _insert_candidate():
                    client = await supabase._ensure()
                    return await client.table("dw_onion_seeds").insert(candidate).execute()

                try:
                    inserted = (await supabase._retry(_insert_candidate, attempts=1)).data or []
                    if not inserted:
                        raise RuntimeError("onion candidate insert returned no row")
                    seed = inserted[0]
                except Exception:
                    # A concurrent crawler may have inserted this URL. Re-read, but
                    # never update status/trust/monitoring flags as a fallback.
                    rows = (await supabase._retry(_lookup, attempts=1)).data or []
                    if not rows:
                        raise
                    seed = rows[0]

            if state not in {"checked", "failed"}:
                continue

            reachable = url in crawler.seed_transport_reached
            outcome = "reachable_unverified" if reachable else "unreachable"
            params = {
                "p_seed_id": str(seed["id"]),
                "p_probe_method": "tor_https_get" if parsed.scheme == "https" else "tor_http_get",
                # An HTTP response via a configured SOCKS proxy is not, by itself,
                # proof of a Tor circuit/stream. Keep this false until ControlPort
                # circuit/stream evidence is collected by the deployed runtime.
                "p_tor_route_verified": False,
                "p_request_url": url,
                "p_http_status": crawler.seed_http_status.get(url),
                "p_response_sha256": crawler.seed_content_hash.get(url),
                "p_content_type": crawler.seed_content_type.get(url),
                "p_response_bytes": crawler.seed_response_bytes.get(url),
                "p_publisher_proof_url": None,
                "p_publisher_proof_verified": False,
                "p_independent_corroboration_url": None,
                "p_independent_corroboration_verified": False,
                "p_provenance_match": False,
                "p_outcome": outcome,
                "p_error_code": None if reachable else "native_onion_transport_failed",
                "p_evidence_metadata": {
                    "seed_origin": crawler.seed_origin.get(url, "configured"),
                    "discovered_from": crawler.discovered_from.get(url),
                    "pages_checked": crawler.pages_checked,
                    "pages_failed": crawler.pages_failed,
                    "tor_route_verification": "not_verified_by_control_port",
                    "publisher_identity": "unverified",
                },
            }
            await supabase.rpc("dw_record_onion_probe_result", params)

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
