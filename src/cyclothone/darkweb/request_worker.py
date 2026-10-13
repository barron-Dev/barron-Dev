from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx

from cyclothone.darkweb.matcher import DarkWebMatcher
from cyclothone.darkweb.pullers import (
    BlueskyPublicMonitor,
    GitHubCodeMonitor,
    HackerNewsPublicMonitor,
    LemmyPublicMonitor,
    PastePublicMonitor,
    RedditPublicMonitor,
    RansomwatchPuller,
    TelegramPublicMonitor,
)
from cyclothone.darkweb.telegram_config import configured_telegram_channels
from cyclothone.darkweb.tiktok import TikTokCommercialContentMonitor
from cyclothone.storage.supabase_client import supabase

logger = logging.getLogger(__name__)
ALLOWED_TYPES = {"domain", "url", "email", "brand", "username", "ip", "other"}


def _is_public_host(host: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        host = host.rstrip(".").lower()
        return bool(host and "." in host and host not in {"localhost", "localhost.localdomain"}
                    and not host.endswith((".local", ".internal", ".localhost", ".test", ".invalid")))


def normalize_target(value: str, target_type: str) -> str:
    target = value.strip()
    if not target or len(target) > 2000 or target_type not in ALLOWED_TYPES:
        raise ValueError("invalid_target")
    if target_type in {"domain", "url"}:
        candidate = target if "://" in target else f"https://{target}"
        parsed = urlsplit(candidate)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("invalid_target")
        host = parsed.hostname.rstrip(".").lower()
        if not _is_public_host(host):
            raise ValueError("private_or_internal_target")
        if target_type == "url":
            return candidate
        if ":" in host:
            raise ValueError("invalid_domain")
        return host
    if target_type == "email":
        if "@" not in target or target.count("@") != 1:
            raise ValueError("invalid_email_target")
        local, domain = target.rsplit("@", 1)
        if not local or "." not in domain or not _is_public_host(domain.lower()):
            raise ValueError("invalid_email_target")
        return f"{local}@{domain.lower()}"
    return target.lower()


def _coverage_state(sources: list[dict]) -> str:
    """Describe configured provider checks, including partial per-provider coverage."""
    checked = any(source.get("state") == "checked" for source in sources)
    if not checked:
        return "none"
    if all(
        source.get("state") == "checked" and source.get("coverage") != "partial"
        for source in sources
    ):
        return "all_configured_sources_checked"
    return "partial"


def _merge_result_findings(persisted: list[dict], historical_exact: list[dict]) -> list[dict]:
    """Merge tenant-owned exact historical matches with this watchlist's findings."""
    merged: dict[str, dict] = {}
    for item in [*persisted, *historical_exact]:
        finding_id = item.get("id")
        if finding_id is None:
            continue
        key = str(finding_id)
        # Prefer the current watchlist representation if the same durable row
        # appears in both sets.
        merged.setdefault(key, {**item, "source_url": _safe_evidence_url(item.get("source_url"))})
    return list(merged.values())


def _merge_evidence_for_findings(evidence: list[dict], findings: list[dict]) -> list[dict]:
    """Ensure each returned durable finding has a provenance entry when possible."""
    merged: dict[str, dict] = {}
    for item in evidence:
        key = str(item.get("content_hash") or "")
        if key:
            merged.setdefault(key, item)
    for finding in findings:
        content_hash = str(finding.get("content_hash") or "")
        if not content_hash or content_hash in merged:
            continue
        merged[content_hash] = {
            "source": finding.get("source_id"),
            "collected_at": finding.get("collected_at") or finding.get("first_seen"),
            "content_hash": content_hash,
            "source_url": _safe_evidence_url(finding.get("source_url")),
            "label": "historical match — review",
        }
    return list(merged.values())


def _alerts_for_findings(alerts: list[dict], findings: list[dict]) -> list[dict]:
    """Select tenant-scoped alerts linked to any finding shown in this result."""
    finding_ids = {str(item.get("id")) for item in findings if item.get("id") is not None}
    return [
        alert for alert in alerts
        if alert.get("finding_id") is not None and str(alert["finding_id"]) in finding_ids
    ]


def _case_resolution(existing_request_case_id: object, alerts: list[dict]) -> dict:
    """Choose a non-duplicating case action without reassigning linked alerts."""
    linked_alert_cases = sorted({
        str(alert["case_id"])
        for alert in alerts
        if alert.get("case_id")
    })
    if existing_request_case_id:
        case_id = str(existing_request_case_id)
        return {
            "case_id": case_id,
            "case_ids": sorted(set([case_id, *linked_alert_cases])),
            "create_case": False,
            "attach_unlinked_alerts": not linked_alert_cases or linked_alert_cases == [case_id],
        }
    if len(linked_alert_cases) == 1:
        return {
            "case_id": linked_alert_cases[0],
            "case_ids": linked_alert_cases,
            "create_case": False,
            "attach_unlinked_alerts": True,
        }
    if len(linked_alert_cases) > 1:
        # Several cases already own alerts for this finding set. A new case
        # would duplicate the investigation, and choosing one would be arbitrary.
        return {
            "case_id": None,
            "case_ids": linked_alert_cases,
            "create_case": False,
            "attach_unlinked_alerts": False,
        }
    return {
        "case_id": None,
        "case_ids": [],
        "create_case": True,
        "attach_unlinked_alerts": True,
    }


def _safe_evidence_url(value: object) -> str | None:
    """Return a directly usable HTTPS evidence URL; never expose appended titles."""
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate or any(char.isspace() or ord(char) < 32 for char in candidate):
        return None
    try:
        parsed = urlsplit(candidate)
        # Evidence links must be absolute HTTPS URLs with a hostname and no
        # embedded credentials. Do not try to salvage malformed URLs by slicing.
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        _ = parsed.port  # Force validation of malformed port values.
    except ValueError:
        return None
    return candidate


def _require_recorded_finding(response: object) -> dict:
    """Require the database RPC to confirm a durable finding and alert."""
    rows = response if isinstance(response, list) else [response]
    for row in rows:
        if isinstance(row, dict) and row.get("finding_id") is not None and row.get("alert_id"):
            return row
    raise RuntimeError("finding_persistence_unconfirmed")


def _finding_matches_target(finding: object, watch_kind: str, watch_value: str) -> bool:
    """Match a provider finding to the monitored identifier without fuzzy guesses.

    HIBP's domain endpoint returns breached email identifiers, not a synthetic
    domain finding. Treat an email as relevant to a domain watch only when its
    normalized domain component is an exact match.
    """
    kind = str(getattr(finding, "kind", "")).strip().lower()
    value = str(getattr(finding, "matched_value", "")).strip().lower()
    expected = watch_value.strip().lower()
    if kind == watch_kind and value == expected:
        return True
    if watch_kind == "domain" and kind == "email":
        local, separator, domain = value.rpartition("@")
        return bool(local and separator and domain.rstrip(".") == expected)
    return False


class DarkWebRequestWorker:
    """Leased worker for customer requests; uses the existing dark-web engine."""

    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._semaphore = asyncio.Semaphore(2)
        self.matcher = DarkWebMatcher()

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._loop(), name="cyclothone-darkweb-requests")

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
        await asyncio.sleep(5)
        while not self._stop.is_set():
            try:
                await supabase.rpc("sweep_expired_service_requests", {})
                rows = await supabase.rpc("claim_service_requests", {
                    "p_service_key": "dark_web_monitoring", "p_limit": 3, "p_lease_seconds": 180
                })
                if not rows:
                    await asyncio.sleep(5)
                    continue
                await asyncio.gather(*(self._guarded(row) for row in rows), return_exceptions=True)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("dark-web request claim cycle failed")
                await asyncio.sleep(5)

    async def _guarded(self, row: dict) -> None:
        async with self._semaphore:
            try:
                await asyncio.wait_for(self._process(row), timeout=150)
            except asyncio.CancelledError:
                raise
            except ValueError as exc:
                logger.warning("dark-web request rejected id=%s reason=%s", row.get("id"), str(exc))
                try:
                    await self._complete(
                        row,
                        "blocked",
                        "blocked",
                        {"service": "dark_web_monitoring", "error": "invalid_target"},
                        str(exc)[:80] or "invalid_target",
                    )
                except Exception:
                    # Includes a rejected fencing token; never bypass the RPC
                    # fence with a direct table update or an unfenced retry.
                    logger.exception("failed to persist dark-web request rejection id=%s", row.get("id"))
            except Exception:
                # Keep the lease. Once it expires, the claim RPC retries the real
                # request; the sweeper blocks it after three attempts.
                logger.exception("dark-web request processing failed id=%s; lease will expire for retry", row.get("id"))

    async def _process(self, request: dict) -> None:
        request_id = str(request["id"])
        target_type = str(request.get("target_type") or "domain")
        target = normalize_target(str(request.get("target") or ""), target_type)
        organization_id = str(request["organization_id"])
        org = await supabase.select_one(
            "customer_organizations", "id,tenant_id", id=organization_id
        )
        if not org or not org.get("tenant_id"):
            await self._complete(request, "blocked", "blocked", {"error": "tenant_unavailable"}, "tenant_unavailable")
            return
        tenant_id = str(org["tenant_id"])
        watch_kind = {"domain": "domain", "url": "domain", "email": "email", "brand": "company_name",
                      "username": "username", "ip": "ip", "other": "other"}[target_type]
        watch_value = (urlsplit(target).hostname or "").lower() if target_type == "url" else target.lower()
        if not watch_value:
            raise ValueError("invalid_target")
        watch_hash = hashlib.sha256(watch_value.encode()).hexdigest()
        existing = await supabase.select_one(
            "dw_watchlist", "id,tenant_id,kind,value,value_hash,severity",
            tenant_id=tenant_id, kind=watch_kind, value_hash=watch_hash,
        )
        watch = existing or await supabase.insert_one("dw_watchlist", {
            "tenant_id": tenant_id, "kind": watch_kind, "value": watch_value,
            "value_hash": watch_hash, "label": f"Customer request: {watch_value}", "severity": "high",
        })
        watch_id = str(watch["id"])

        # Exact retro-sweep only; findings are labeled as review candidates.
        historical = await supabase.select(
            "dw_findings",
            "id,source_id,content_hash,kind,matched_value,context,source_url,severity,first_seen,collected_at,tenant_id,watchlist_id",
            tenant_id=tenant_id,
        )
        exact = [f for f in historical if str(f.get("kind", "")).lower() == watch_kind
                 and str(f.get("matched_value", "")).strip().lower() == watch_value]
        enabled_rows = await supabase.select("dw_sources", "id,enabled,last_status,last_pull_at", enabled=True)
        enabled = {str(x["id"]) for x in enabled_rows}
        sources: list[dict] = []
        pulled = []
        findings = []
        github_token = (os.getenv("CYCLOTHONE_GITHUB_TOKEN") or os.getenv("SENTINEL_GITHUB_TOKEN") or "").strip()
        youtube_api_key = (os.getenv("CYCLOTHONE_YOUTUBE_API_KEY") or "").strip()
        telegram_channels = configured_telegram_channels(use_defaults=False)
        reddit_credentials = bool(
            (os.getenv("CYCLOTHONE_REDDIT_CLIENT_ID") or "").strip()
            and (os.getenv("CYCLOTHONE_REDDIT_CLIENT_SECRET") or "").strip()
        )
        tiktok_client_key = (os.getenv("CYCLOTHONE_TIKTOK_CLIENT_KEY") or "").strip()
        tiktok_client_secret = (os.getenv("CYCLOTHONE_TIKTOK_CLIENT_SECRET") or "").strip()
        tiktok_credentials = bool(tiktok_client_key and tiktok_client_secret)
        tiktok_supported_target = target_type in {"domain", "url", "brand", "username"}
        tiktok_reason = (
            "missing_api_credentials" if not tiktok_credentials
            else ("unsupported_target_type" if not tiktok_supported_target else None)
        )
        provider_domain = watch_value if target_type in {"domain", "url"} else ""
        provider_email = watch_value if target_type == "email" else ""
        async def run_source(source_id: str, pull, timeout: int, unavailable_reason: str | None = None):
            if source_id not in enabled:
                return {"source": source_id, "state": "unavailable", "reason": "disabled"}, []
            if unavailable_reason:
                return {"source": source_id, "state": "unavailable", "reason": unavailable_reason}, []
            if pull is None:
                return {"source": source_id, "state": "unavailable", "reason": "unsupported_target_type"}, []
            try:
                findings = await asyncio.wait_for(pull(), timeout=timeout)
                monitor = getattr(pull, "__self__", None)
                channel_status = getattr(monitor, "channel_status", {})
                failed_channels = [
                    channel for channel, state in channel_status.items()
                    if state != "checked"
                ]
                if channel_status:
                    return {
                        "source": source_id,
                        "state": "checked",
                        "coverage": "partial" if failed_channels else "all_configured_channels_checked",
                        "channels": [
                            {"channel": channel, "state": state}
                            for channel, state in sorted(channel_status.items())
                        ],
                    }, findings
                return {"source": source_id, "state": "checked"}, findings
            except Exception:
                logger.warning("dark-web provider request failed source=%s request_id=%s", source_id, request_id, exc_info=True)
                return {"source": source_id, "state": "failed", "reason": "source_request_failed"}, []

        # The upstream Ransomwatch corpus is archived. Keep it out of live
        # coverage and current alerts until a maintained source is verified.
        ransom_reason = (
            "historical_only_archived_feed"
            if target_type in {"domain", "url", "brand"}
            else "unsupported_target_type"
        )
        github_reason = "missing_key" if not github_token else ("unsupported_target_type" if not provider_domain else None)
        public_target_supported = target_type in {"domain", "url", "email"}
        telegram_target_supported = target_type in {"domain", "url", "email", "brand", "username"}
        paste_reason = None if public_target_supported else "unsupported_target_type"
        telegram_reason = (
            "unsupported_target_type" if not telegram_target_supported
            else ("missing_channels" if not telegram_channels else None)
        )
        telegram_monitor = (
            TelegramPublicMonitor(telegram_channels, target_type=target_type, target=watch_value)
            if telegram_channels and telegram_target_supported else None
        )
        social_reason = None if provider_domain else "unsupported_target_type"
        reddit_reason = (
            "missing_api_credentials" if not reddit_credentials
            else social_reason
        )
        youtube_reason = (
            "missing_api_key" if not youtube_api_key
            else social_reason
        )
        provider_specs = [
            ("ransomwatch", RansomwatchPuller().pull if not ransom_reason else None, 35, ransom_reason),
            ("github_code", (lambda: GitHubCodeMonitor(github_token).pull_domain(provider_domain)) if github_token and provider_domain else None, 65, github_reason),
            ("pastebin_public", PastePublicMonitor().pull if public_target_supported else None, 50, paste_reason),
            ("telegram_public", telegram_monitor.pull if telegram_monitor else None, 90, telegram_reason),
            ("youtube_public", (lambda: YouTubePublicMonitor(youtube_api_key).pull_domains([provider_domain])) if youtube_api_key and provider_domain else None, 45, youtube_reason),
            # Public social/community sources are checked in the same customer request,
            # so the result reports each source's real outcome instead of scheduler-only status.
            ("bluesky_public", (lambda: BlueskyPublicMonitor().pull_domains([provider_domain])) if provider_domain else None, 45, social_reason),
            ("reddit_public", (lambda: RedditPublicMonitor().pull_domains([provider_domain])) if provider_domain and reddit_credentials else None, 45, reddit_reason),
            ("hackernews_public", (lambda: HackerNewsPublicMonitor().pull_domains([provider_domain])) if provider_domain else None, 45, social_reason),
            ("lemmy_public", (lambda: LemmyPublicMonitor().pull_domains([provider_domain])) if provider_domain else None, 45, social_reason),
            ("tiktok_commercial", (lambda: TikTokCommercialContentMonitor().pull_target(watch_kind, watch_value)) if tiktok_credentials and tiktok_supported_target else None, 60, tiktok_reason),
        ]
        provider_results = await asyncio.gather(*(
            run_source(source_id, pull, timeout, reason)
            for source_id, pull, timeout, reason in provider_specs
        ))
        sources = [status for status, _ in provider_results]
        pulled = [finding for _, batch in provider_results for finding in batch]

        # A completed search requires at least one provider call to succeed.
        # An empty result from a checked source is a valid zero-match result;
        # all-failed/all-unavailable is not a successful search.
        if not any(source["state"] == "checked" for source in sources):
            failure_result = {
                "service": "dark_web_monitoring",
                "target": watch_value,
                "target_type": target_type,
                "outcome": "source_unavailable",
                "coverage": "none",
                "sources_checked": [],
                "sources_unavailable": [source for source in sources if source["state"] != "checked"],
                "findings": [],
                "evidence": [],
                "alerts": [],
                "completed_at": datetime.now(UTC).isoformat(),
            }
            await self._complete(
                request, "failed", "failed", failure_result, "no_source_checked"
            )
            return

        # Persist only exact target matches. The global feed itself is still
        # useful for retro-sweep but a company-name resemblance is never silently
        # promoted to a confirmed match.
        evidence = []
        persistence_failures = 0
        for item in exact:
            evidence.append({
                "source": item.get("source_id"), "collected_at": item.get("collected_at") or item.get("first_seen"),
                "content_hash": item.get("content_hash"), "source_url": _safe_evidence_url(item.get("source_url")),
                "label": "possible match — review",
            })
        for finding in pulled[:2000]:
            if not _finding_matches_target(finding, watch_kind, watch_value):
                continue
            meta = dict(finding.metadata or {})
            meta["customer_match"] = "exact"
            tenant_hash = hashlib.sha256(f"{getattr(finding, 'source_id', '')}:{hashlib.sha256((str(finding.matched_value).strip().lower()).encode()).hexdigest()}:{watch_id}".encode()).hexdigest()
            try:
                recorded = await supabase.rpc("record_dw_finding", {
                    "p_source_id": finding.source_id, "p_content_hash": tenant_hash,
                    "p_kind": finding.kind, "p_matched_value": str(finding.matched_value).strip().lower(),
                    "p_context": finding.context, "p_severity": finding.severity,
                    "p_source_url": _safe_evidence_url(finding.source_url), "p_metadata": meta,
                    "p_tenant_id": tenant_id, "p_watchlist_id": watch_id,
                })
                _require_recorded_finding(recorded)
                evidence.append({"source": finding.source_id, "collected_at": datetime.now(UTC).isoformat(),
                                 "content_hash": tenant_hash, "source_url": _safe_evidence_url(finding.source_url)})
            except Exception:
                persistence_failures += 1
                logger.warning("unable to persist customer dark-web match", exc_info=True)

        # Never report a completed search if one or more exact matches could not
        # be durably persisted. Let the lease expire so the request can retry.
        if persistence_failures:
            raise RuntimeError("finding_persistence_incomplete")

        # Re-read tenant-scoped findings for this watchlist and keep result evidence bounded.
        persisted = await supabase.select(
            "dw_findings",
            "id,source_id,content_hash,matched_value,context,source_url,severity,first_seen,collected_at,watchlist_id",
            tenant_id=tenant_id, watchlist_id=watch_id,
        )
        # The watchlist may already have findings from the continuous scheduler.
        # Include those durable rows in the explicit evidence collection as well;
        # otherwise the result can list a finding without its corresponding evidence.
        evidence_by_hash = {
            str(item.get("content_hash") or ""): item
            for item in evidence
            if item.get("content_hash")
        }
        for item in persisted:
            content_hash = str(item.get("content_hash") or "")
            if not content_hash:
                continue
            evidence_by_hash.setdefault(content_hash, {
                "source": item.get("source_id"),
                "collected_at": item.get("collected_at") or item.get("first_seen"),
                "content_hash": content_hash,
                "source_url": _safe_evidence_url(item.get("source_url")),
                "label": "possible match — review",
            })
        evidence = list(evidence_by_hash.values())
        # Apply the same provenance boundary to finding links shown in the
        # customer result; this does not mutate historical database rows.
        result_findings = _merge_result_findings(persisted, exact)
        # Historical matches must carry their own evidence references too;
        # otherwise a finding can appear in the result without provenance.
        evidence = _merge_evidence_for_findings(evidence, result_findings)
        alerts = await supabase.select(
            "dw_alerts",
            "id,title,summary,severity,status,finding_id,created_at,case_id",
            tenant_id=tenant_id,
        )
        relevant_alerts = _alerts_for_findings(alerts, result_findings)
        case_id = None
        case_ids: list[str] = []
        if relevant_alerts:
            # The request link is the retry idempotency anchor. Scope it to the
            # request's organization and verify the linked case belongs to the tenant.
            existing_link = await supabase.select_one(
                "customer_case_links", "case_id",
                service_request_id=request_id, organization_id=organization_id,
            )
            if existing_link and not existing_link.get("case_id"):
                raise RuntimeError("case_link_missing_case_id")
            plan = _case_resolution(
                existing_link.get("case_id") if existing_link else None,
                relevant_alerts,
            )
            case_id = plan["case_id"]
            case_ids = list(plan["case_ids"])
            if case_id:
                owned_case = await supabase.select_one(
                    "crime_cases", "id,tenant_id", id=case_id, tenant_id=tenant_id,
                )
                if not owned_case:
                    raise RuntimeError("case_link_tenant_mismatch")
            elif plan["create_case"]:
                requester_user_id = str(request.get("requester_user_id") or "").strip()
                if not requester_user_id:
                    raise RuntimeError("case_link_requester_missing")
                case_number = await supabase.rpc("next_case_number", {"p_tenant": tenant_id})
                case = await supabase.insert_one("crime_cases", {
                    "tenant_id": tenant_id, "case_number": str(case_number),
                    "title": f"Dark Web Monitoring — {watch_value[:120]}",
                    "category": "other", "severity": max(
                        (str(a.get("severity", "medium")).lower() for a in relevant_alerts),
                        key=lambda value: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(value, 2),
                        default="medium",
                    ),
                    "status": "open", "summary": f"Exact dark-web exposure match for {watch_value}.",
                    "evidence": evidence[:200],
                })
                case_id = str(case["id"])
                case_ids = [case_id]
            if plan["attach_unlinked_alerts"] and case_id:
                for alert in relevant_alerts:
                    if not alert.get("case_id"):
                        await supabase.update(
                            "dw_alerts", {"case_id": case_id},
                            id=str(alert["id"]), tenant_id=tenant_id,
                        )
                        alert["case_id"] = case_id
            # Link only after the alert rows point at the case. If link persistence
            # fails, a retry can recover the case from those durable alert links.
            if case_id and not existing_link:
                requester_user_id = str(request.get("requester_user_id") or "").strip()
                if not requester_user_id:
                    raise RuntimeError("case_link_requester_missing")
                await supabase.insert_one("customer_case_links", {
                    "organization_id": organization_id,
                    "service_request_id": request_id,
                    "case_id": case_id,
                    "created_by": requester_user_id,
                })
            case_ids = sorted(set([*case_ids, *[
                str(alert["case_id"]) for alert in relevant_alerts if alert.get("case_id")
            ]]))
            if len(case_ids) != 1:
                case_id = None
            elif case_ids:
                case_id = case_ids[0]
        checked_sources = [x for x in sources if x["state"] == "checked"]
        unavailable_sources = [x for x in sources if x["state"] != "checked"]
        # Coverage describes this configured provider set only; it never claims
        # visibility into the entire dark web or unconfigured services.
        coverage = _coverage_state(sources)
        result = {
            "service": "dark_web_monitoring", "target": watch_value, "target_type": target_type,
            "coverage": coverage, "sources_checked": checked_sources,
            "sources_unavailable": unavailable_sources,
            "findings": result_findings[:200], "evidence": evidence[:200], "alerts": relevant_alerts[:200],
            "case_id": case_id, "case_ids": case_ids, "alert_count": len(relevant_alerts),
            "recommendations": (
                ["Review each possible match against the source evidence.", "Rotate exposed credentials and investigate affected accounts."]
                if result_findings else ["No exact matches were confirmed in the sources checked.",
                                          "Coverage is partial; unavailable sources were not searched."]
            ),
            "completed_at": datetime.now(UTC).isoformat(),
        }
        await self._complete(request, "succeeded", "resolved", result, None)

    async def _complete(self, request: dict, state: str, status: str, result: dict, failure_code: str | None) -> None:
        # The attempt number is a fencing token: a stale worker cannot overwrite
        # a newer lease or a terminal result after its lease has been reclaimed.
        completed = await supabase.rpc("complete_service_request", {
            "p_id": str(request["id"]), "p_attempt": int(request["attempts"]),
            "p_state": state, "p_status": status,
            "p_result": result, "p_failure_code": failure_code,
        })
        if completed is not True:
            # False means the lease/attempt fence rejected this completion.
            # Do not claim success or try an unfenced fallback write.
            raise RuntimeError("completion_fence_rejected")
