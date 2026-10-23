from __future__ import annotations

import asyncio
import logging
import os
import time
from urllib.parse import urlsplit
from datetime import UTC, datetime

from cyclothone.darkweb.matcher import DarkWebMatcher
from cyclothone.darkweb.native_onion import NativeOnionCrawler, configured_onion_seeds
from cyclothone.darkweb.pullers import PastePublicMonitor, RansomwatchPuller, TelegramPublicMonitor
from cyclothone.darkweb.telegram_config import (
    DEFAULT_PUBLIC_TELEGRAM_CHANNELS,  # noqa: F401 — compatibility export
    configured_telegram_channels,
)
from cyclothone.storage.supabase_client import supabase

logger = logging.getLogger(__name__)


def _configured_telegram_channels() -> list[str]:
    return configured_telegram_channels()


def _current_ransomwatch_findings(findings: list) -> list:
    """Only fresh, dated feed records may enter the global current-alert pipeline."""
    return [
        finding for finding in findings
        if isinstance(getattr(finding, "metadata", None), dict)
        and finding.metadata.get("temporal_class") == "current_feed"
    ]


def _require_temporal_archive_confirmation(response: object, expected: int) -> None:
    """Require the database to confirm every source-level temporal record write."""
    rows = response if isinstance(response, list) else [response]
    for row in rows:
        if isinstance(row, dict):
            try:
                if int(row.get("accepted_count", -1)) == expected:
                    return
            except (TypeError, ValueError):
                continue
    raise RuntimeError("ransomwatch_temporal_archive_unconfirmed")


class DarkWebScheduler:
    GLOBAL_INTERVAL = 15 * 60
    DOMAIN_INTERVAL = 6 * 3600
    STARTUP_DELAY = 30

    def __init__(self) -> None:
        self.matcher = DarkWebMatcher()
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._last_domain = 0.0
        self._last_ransomwatch_pull = 0.0
        self._onion_evidence_persisted_this_tick = False

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
        # Poll the public aggregate feed on its 30-minute cadence. Current dated
        # entries are live feed intelligence; older entries remain historical, and
        # this is never represented as direct Tor access to a leak site.
        if (
            "ransomwatch" in enabled
            and time.monotonic() - self._last_ransomwatch_pull >= 30 * 60
        ):
            ransomwatch = RansomwatchPuller()
            await self._run_pull("ransomwatch", ransomwatch.pull, monitor=ransomwatch)
            self._last_ransomwatch_pull = time.monotonic()
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
                    .eq("monitoring_enabled", True)
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
        # Native onion polling must remain explicitly opt-in. The source registry's
        # enabled flag and configured seed env var are not sufficient authorization
        # to start probing; keep this disabled unless an operator deliberately sets
        # the dedicated runtime flag after route, scope, and release checks.
        native_onion_enabled = os.getenv("CYCLOTHONE_DW_NATIVE_ONION_ENABLED", "false").strip().lower() in {
            "1", "true", "yes", "on"
        }
        if not native_onion_enabled:
            logger.info("native onion monitoring disabled by CYCLOTHONE_DW_NATIVE_ONION_ENABLED")
            return

        self._onion_evidence_persisted_this_tick = False
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
            if source_id == "ransomwatch":
                if monitor is None or not getattr(monitor, "feed_checked", False):
                    raise RuntimeError("ransomwatch_feed_not_confirmed")
                temporal_records = getattr(monitor, "temporal_records", None)
                if not isinstance(temporal_records, list):
                    raise RuntimeError("ransomwatch_temporal_records_missing")
                # Persist all three time classes before any current alert is ingested.
                # If archive persistence fails, do not create partial current alerts.
                archive_result = await supabase.rpc(
                    "record_ransomwatch_temporal_records",
                    {"p_records": temporal_records[:5000]},
                )
                _require_temporal_archive_confirmation(archive_result, len(temporal_records[:5000]))
                # The scheduler is the current-alert path. Historical entries are
                # durable archive-only records; future-dated entries are quarantined.
                findings = _current_ransomwatch_findings(findings)
            if (
                source_id == "native_onion"
                and monitor is not None
                and not self._onion_evidence_persisted_this_tick
            ):
                await self._persist_onion_seed_state(monitor)
                self._onion_evidence_persisted_this_tick = True
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
            if (
                source_id == "native_onion"
                and monitor is not None
                and not self._onion_evidence_persisted_this_tick
            ):
                try:
                    await self._persist_onion_seed_state(monitor)
                    self._onion_evidence_persisted_this_tick = True
                except Exception as evidence_exc:
                    logger.error(
                        "native onion failure evidence persistence failed error=%s",
                        type(evidence_exc).__name__,
                    )
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
        if not crawler.seed_status:
            return

        client = await supabase._ensure()
        # Persist discovered links as candidate inventory without treating them as probed seeds.
        urls = list(dict.fromkeys(
            list(crawler.seed_status)
            + [row["url"] for row in crawler.discovered_seeds if row.get("url")]
        ))
        hosts = sorted({
            (urlsplit(url).hostname or "").lower()
            for url in urls
            if urlsplit(url).hostname
        })
        existing_by_host: dict[str, dict] = {}
        for offset in range(0, len(hosts), 100):
            batch = hosts[offset:offset + 100]
            result = await client.table("dw_onion_seeds").select(
                "id,url,hostname,seed_type,monitoring_enabled"
            ).in_("hostname", batch).execute()
            for row in result.data or []:
                host = str(row.get("hostname") or "").lower()
                if host:
                    existing_by_host[host] = row

        # Newly discovered onion links are inventory candidates only. Never enable
        # monitoring here; actual probe evidence is recorded separately below.
        missing_rows = []
        for url in urls:
            parsed = urlsplit(url)
            host = (parsed.hostname or "").lower()
            if not host or host in existing_by_host:
                continue
            missing_rows.append({
                "url": url,
                "hostname": host,
                "seed_origin": crawler.seed_origin.get(url, "configured"),
                "discovered_from": crawler.discovered_from.get(url),
                "status": "candidate",
                "category_slug": "unclassified",
                "source_role": "candidate_onion_service",
                "requires_tor_probe": True,
                "monitoring_enabled": False,
                "candidate_trust": "candidate",
                "probe_metadata": {
                    "tor_route_verified": False,
                    "reachability_verified": False,
                    "publisher_identity_verified": False,
                    "customer_matching_allowed": False,
                },
            })
        for offset in range(0, len(missing_rows), 100):
            await client.table("dw_onion_seeds").insert(
                missing_rows[offset:offset + 100]
            ).execute()
        if missing_rows:
            for offset in range(0, len(hosts), 100):
                batch = hosts[offset:offset + 100]
                result = await client.table("dw_onion_seeds").select(
                    "id,url,hostname,seed_type,monitoring_enabled"
                ).in_("hostname", batch).execute()
                for row in result.data or []:
                    host = str(row.get("hostname") or "").lower()
                    if host:
                        existing_by_host[host] = row

        for url, state in crawler.seed_status.items():
            parsed = urlsplit(url)
            host = (parsed.hostname or "").lower()
            seed_row = existing_by_host.get(host)
            if not seed_row or not seed_row.get("id"):
                logger.warning("onion probe evidence not persisted: seed row unavailable host=%s", host)
                continue
            probe = crawler.seed_probe_evidence.get(url, {})
            http_status = probe.get("http_status")
            digest = probe.get("response_sha256")
            response_bytes = int(probe.get("response_bytes") or 0)
            # A response obtained through a configured proxy is not by itself
            # proof that the proxy is a trusted Tor route. Keep that flag false
            # until the runtime route is independently validated.
            has_http_content = (
                isinstance(http_status, int)
                and 200 <= http_status < 300
                and isinstance(digest, str)
                and len(digest) == 64
                and response_bytes > 0
            )
            http_response_received = isinstance(http_status, int) and 200 <= http_status < 300
            outcome = "reachable_unverified" if http_response_received else "unreachable"
            error_code = probe.get("error_code")
            metadata = {
                "collector": "native_onion",
                "seed_state": state,
                "seed_origin": crawler.seed_origin.get(url, "configured"),
                "discovered_from": crawler.discovered_from.get(url),
                "tor_route_verified": False,
                "publisher_identity_verified": False,
                "customer_matching_allowed": False,
                "content_inspected": bool(has_http_content),
                "response_bytes": response_bytes,
                "response_sha256": digest,
            }
            try:
                await supabase.rpc(
                    "dw_record_onion_probe_result",
                    {
                        "p_seed_id": str(seed_row["id"]),
                        "p_probe_method": "tor_https_get" if parsed.scheme == "https" else "tor_http_get",
                        "p_tor_route_verified": False,
                        "p_request_url": url,
                        "p_http_status": http_status,
                        "p_response_sha256": digest,
                        "p_content_type": probe.get("content_type"),
                        "p_response_bytes": response_bytes,
                        "p_publisher_proof_url": None,
                        "p_publisher_proof_verified": False,
                        "p_independent_corroboration_url": None,
                        "p_independent_corroboration_verified": False,
                        "p_provenance_match": False,
                        "p_outcome": outcome,
                        "p_error_code": str(error_code)[:120] if error_code else None,
                        "p_evidence_metadata": metadata,
                    },
                )
            except Exception as exc:
                logger.error(
                    "onion probe evidence persistence failed host=%s error=%s",
                    host,
                    type(exc).__name__,
                )

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
