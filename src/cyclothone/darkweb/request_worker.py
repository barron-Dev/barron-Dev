from __future__ import annotations

import asyncio
import hashlib
import logging
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx

from cyclothone.darkweb.matcher import DarkWebMatcher
from cyclothone.darkweb.native_onion import NativeOnionCrawler, configured_onion_seeds
from cyclothone.darkweb.pullers import (
    BlueskyPublicMonitor,
    PastePublicMonitor,
    RansomwatchPuller,
    TelegramPublicMonitor,
)
from cyclothone.darkweb.telegram_config import configured_telegram_channels
from cyclothone.storage.supabase_client import supabase
from cyclothone.darkweb.source_catalog import get_source, is_excluded_source
from cyclothone.darkweb.evidence_store import record_target_matched_onion_evidence

logger = logging.getLogger(__name__)
ALLOWED_TYPES = {"domain", "url", "email", "brand", "username", "ip", "other"}


class InvalidTargetError(ValueError):
    """Only target-normalization failures that should block a request."""



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
        raise InvalidTargetError("invalid_target")
    if target_type in {"domain", "url"}:
        candidate = target if "://" in target else f"https://{target}"
        parsed = urlsplit(candidate)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise InvalidTargetError("invalid_target")
        host = parsed.hostname.rstrip(".").lower()
        if not _is_public_host(host):
            raise InvalidTargetError("private_or_internal_target")
        if target_type == "url":
            return candidate
        if ":" in host:
            raise InvalidTargetError("invalid_domain")
        return host
    if target_type == "email":
        if "@" not in target or target.count("@") != 1:
            raise InvalidTargetError("invalid_email_target")
        local, domain = target.rsplit("@", 1)
        if not local or "." not in domain or not _is_public_host(domain.lower()):
            raise InvalidTargetError("invalid_email_target")
        return f"{local}@{domain.lower()}"
    return target.lower()


def _coverage_state(sources: list[dict]) -> str:
    """Summarize implemented live sources without treating archived/planned entries as checks."""
    live_sources = [source for source in sources if source.get("availability", "implemented") == "implemented"]
    if not any(source.get("state") == "checked" for source in live_sources):
        return "none"
    if all(
        source.get("state") == "checked" and source.get("coverage") != "partial"
        for source in live_sources
    ):
        # Keep the existing API enum stable for clients; denominator now
        # includes only implemented live sources as documented above.
        return "all_configured_sources_checked"
    return "partial"


def _requester_actor(request: dict) -> str:
    """Return the authenticated request owner required by case-link audit rows."""
    actor = request.get("requester_user_id")
    if not actor:
        raise RuntimeError("case_link_requester_missing")
    return str(actor)


def _source_is_enabled(source_id: str, enabled_source_ids: set[str], registered_source_ids: set[str]) -> bool:
    """Honor operator disablement; use config-only fallback only before native source registration."""
    if source_id in enabled_source_ids:
        return True
    return source_id == "native_onion" and source_id not in registered_source_ids


def _require_recorded_finding(response: object) -> dict:
    """Require the database RPC to confirm a durable finding and alert."""
    rows = response if isinstance(response, list) else [response]
    for row in rows:
        if isinstance(row, dict) and row.get("finding_id") is not None and row.get("alert_id"):
            return row
    raise RuntimeError("finding_persistence_unconfirmed")


def _is_current_finding(item: dict, request_id: str) -> bool:
    """Keep historical archives out of current results without promoting legacy rows."""
    source_id = str(item.get("source_id") or "").lower()
    metadata = item.get("source_metadata")
    if source_id == "ransomwatch":
        if not isinstance(metadata, dict):
            return False
        if str(metadata.get("temporal_class") or "") != "current_feed":
            return False
        # Scheduled global polling has no customer request ID; request-triggered
        # checks do. If present, the request binding must match exactly.
        bound_request = str(metadata.get("service_request_id") or "")
        if bound_request and bound_request != str(request_id):
            return False
        try:
            observed = datetime.fromisoformat(str(metadata.get("feed_observed_at") or "").replace("Z", "+00:00"))
            published = datetime.fromisoformat(str(metadata.get("published") or "").replace("Z", "+00:00"))
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=UTC)
            if published.tzinfo is None:
                published = published.replace(tzinfo=UTC)
            now = datetime.now(UTC)
            if (now - observed.astimezone(UTC)).total_seconds() > 3600:
                return False
            age = (now - published.astimezone(UTC)).total_seconds()
            return -300 <= age <= 30 * 86400
        except (TypeError, ValueError):
            return False
    if str(item.get("finding_class") or "") != "historical_archive":
        return True
    if not isinstance(metadata, dict) or str(metadata.get("service_request_id") or "") != str(request_id):
        return False
    # Surface findings are bound by the successful finding RPC for this request.
    # Native onion additionally requires its separately stored durable evidence.
    if source_id == "native_onion":
        return isinstance(metadata.get("durable_evidence"), dict)
    return True


_REQUIRED_ONION_ROUTE_PROOFS = (
    "route_verified",
    "hs_desc_content_received",
    "descriptor_fetched",
    "rendezvous_hop_verified",
    "stream_circuit_bound",
)

_REQUIRED_ONION_CONTROL_ASSERTIONS = (
    "tor_control_authenticated",
    "tor_bootstrap_complete",
    "hsfetch_accepted",
)


def _native_onion_route_proof_missing(monitor: object) -> list[str]:
    """Require per-seed Tor proof bound to the content actually inspected."""
    content_hashes = getattr(monitor, "seed_content_hash", {})
    proofs_by_seed = getattr(monitor, "seed_route_proofs", {})
    if not isinstance(content_hashes, dict) or not content_hashes:
        return list(_REQUIRED_ONION_ROUTE_PROOFS)
    if not isinstance(proofs_by_seed, dict):
        return list(_REQUIRED_ONION_ROUTE_PROOFS)
    missing: set[str] = set()
    for seed in content_hashes:
        proof = proofs_by_seed.get(seed)
        if not isinstance(proof, dict):
            missing.update(_REQUIRED_ONION_ROUTE_PROOFS)
            continue
        # Proof must bind to this exact request and the digest of this seed's
        # inspected response; global daemon health is not per-response evidence.
        if (
            not getattr(monitor, "service_request_id", "")
            or str(proof.get("service_request_id") or "") != str(monitor.service_request_id)
            or str(proof.get("content_sha256") or "").lower() != str(content_hashes[seed]).lower()
            or any(proof.get(field) is not True for field in _REQUIRED_ONION_CONTROL_ASSERTIONS)
        ):
            missing.update(_REQUIRED_ONION_ROUTE_PROOFS)
            continue
        for field in _REQUIRED_ONION_ROUTE_PROOFS:
            if proof.get(field) is not True:
                missing.add(field)
    return [field for field in _REQUIRED_ONION_ROUTE_PROOFS if field in missing]


def _native_onion_route_proof_state(monitor: object) -> dict[str, bool]:
    """Expose aggregate proof only when every inspected seed has its own proof."""
    missing = set(_native_onion_route_proof_missing(monitor))
    return {field: field not in missing for field in _REQUIRED_ONION_ROUTE_PROOFS}


def _native_onion_seed_route_proven(monitor: object, seed: str) -> bool:
    """Require every proof field plus request and exact response-digest binding."""
    proofs = getattr(monitor, "seed_route_proofs", {})
    hashes = getattr(monitor, "seed_content_hash", {})
    proof = proofs.get(seed) if isinstance(proofs, dict) else None
    digest = hashes.get(seed) if isinstance(hashes, dict) else None
    if not isinstance(proof, dict) or not isinstance(digest, str):
        return False
    if not getattr(monitor, "service_request_id", ""):
        return False
    if str(proof.get("service_request_id") or "") != str(monitor.service_request_id):
        return False
    if str(proof.get("content_sha256") or "").lower() != digest.lower():
        return False
    if any(proof.get(field) is not True for field in _REQUIRED_ONION_CONTROL_ASSERTIONS):
        return False
    return all(proof.get(field) is True for field in _REQUIRED_ONION_ROUTE_PROOFS)


def _native_onion_protocol_evidence(monitor: object) -> dict:
    """Summarize request-scoped Tor control proof without retaining descriptor data."""
    proofs = getattr(monitor, "seed_route_proofs", {})
    per_seed = []
    if isinstance(proofs, dict):
        for seed_url, proof in proofs.items():
            if not isinstance(proof, dict):
                continue
            per_seed.append({
                "seed_host": (urlsplit(str(seed_url)).hostname or "").lower(),
                "service_request_id": str(proof.get("service_request_id") or ""),
                "content_sha256": str(proof.get("content_sha256") or "").lower() or None,
                "descriptor_event_count": int(proof.get("descriptor_event_count") or 0),
                "proof": {
                    field: proof.get(field) is True
                    for field in _REQUIRED_ONION_ROUTE_PROOFS
                },
            })
    return {
        "status": str(getattr(monitor, "tor_control_status", "disabled")),
        "control_authenticated": getattr(monitor, "tor_control_authenticated", False) is True,
        "bootstrap_complete": getattr(monitor, "tor_bootstrap_complete", False) is True,
        "tor_version": getattr(monitor, "tor_version", None),
        "seed_proofs": per_seed,
    }


def _native_onion_content_sha256(monitor: object) -> str | None:
    """Return a real response digest only when the collector recorded one."""
    for digest in getattr(monitor, "seed_content_hash", {}).values():
        if (
            isinstance(digest, str)
            and len(digest) == 64
            and all(char in "0123456789abcdefABCDEF" for char in digest)
        ):
            return digest.lower()
    return None


def _native_onion_content_proof_missing(monitor: object) -> list[str]:
    """Require an actual response digest and at least one inspected page."""
    missing = []
    if _native_onion_content_sha256(monitor) is None:
        missing.append("content_sha256")
    if int(getattr(monitor, "pages_checked", 0) or 0) <= 0:
        missing.append("inspected_items")
    return missing


def _native_onion_unavailability(monitor: object) -> tuple[str | None, list[str], list[str]]:
    """Decide whether native onion results may be treated as checked."""
    route_missing = _native_onion_route_proof_missing(monitor)
    content_missing = _native_onion_content_proof_missing(monitor)
    if route_missing:
        return "tor_route_proof_unavailable", route_missing, content_missing
    if content_missing:
        return "onion_content_proof_unavailable", route_missing, content_missing
    return None, [], []


def _source_inspected_items(source: dict) -> int:
    """Count only source-reported inspected content/pages, never seed inventory."""
    return max(
        int(source.get("pages_checked") or 0),
        int(source.get("posts_checked") or 0),
        int(source.get("items_checked") or 0),
        int(source.get("documents_checked") or 0),
        int(source.get("items_inspected") or 0),
    )


def _finding_matches_target(finding: object, watch_kind: str, watch_value: str) -> bool:
    """Match a provider finding or persisted row without fuzzy guesses."""
    if isinstance(finding, dict):
        kind = str(finding.get("kind") or "").strip().lower()
        raw_value = finding.get("matched_value")
    else:
        kind = str(getattr(finding, "kind", "")).strip().lower()
        raw_value = getattr(finding, "matched_value", "")
    value = str(raw_value or "").strip().lower()
    expected = watch_value.strip().lower()
    if kind == watch_kind and value == expected:
        return True
    # A domain monitor should also surface historical exact email-address
    # matches at that domain, but must never promote a subdomain/suffix guess.
    if watch_kind == "domain" and kind == "email":
        local, separator, domain = value.rpartition("@")
        return bool(local and separator and domain.rstrip(".") == expected)
    return False


def _partition_ransomwatch_findings(findings: list, watch_kind: str, watch_value: str) -> tuple[list, list[dict], list[dict]]:
    """Separate current feed hits from historical review candidates and future quarantine."""
    current = []
    historical = []
    future = []
    for finding in findings:
        metadata = finding.metadata if isinstance(getattr(finding, "metadata", None), dict) else {}
        temporal_class = str(metadata.get("temporal_class") or "historical_archive")
        if temporal_class == "current_feed":
            # A fresh global feed entry is not automatically a match for this
            # customer's target. Enforce exact target matching before alerting.
            if _finding_matches_target(finding, watch_kind, watch_value):
                current.append(finding)
            continue
        if temporal_class not in {"historical_archive", "future_dated"}:
            # Unknown classes are fail-closed and never enter the alert path.
            continue
        if not _finding_matches_target(finding, watch_kind, watch_value):
            continue
        candidate = {
            "source": "ransomwatch",
            "source_url": finding.source_url,
            "published": metadata.get("published"),
            "feed_observed_at": metadata.get("feed_observed_at"),
            "victim_name": metadata.get("victim_name") or finding.matched_value,
            "group": metadata.get("group"),
            "temporal_class": temporal_class,
            "label": (
                "future-dated feed entry — quarantined, not an alert"
                if temporal_class == "future_dated"
                else "historical feed match — review; not a current exposure alert"
            ),
        }
        (future if temporal_class == "future_dated" else historical).append(candidate)
    return current, historical, future


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
            except InvalidTargetError as exc:
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

    async def _onion_seed_urls(self) -> tuple[list[str], dict[str, str], dict[str, str]]:
        """Merge explicit seeds with previously checked/failed discovered onion sources."""
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
            # An unapplied source-registry migration must not be hidden as a
            # successful discovery; explicit environment seeds can still be used.
            logger.warning("native onion seed registry unavailable", exc_info=True)
        return seeds[:50], origins, discovered_from

    async def _persist_onion_seed_state(self, crawler: NativeOnionCrawler) -> None:
        """Persist seed inventory without asserting reachability absent Tor-route proof."""
        rows = []
        route_proven = not _native_onion_route_proof_missing(crawler)
        for url, state in crawler.seed_status.items():
            parsed = urlsplit(url)
            hostname = (parsed.hostname or "").lower()
            digest = crawler.seed_content_hash.get(url)
            digest_valid = (
                isinstance(digest, str)
                and len(digest) == 64
                and all(char in "0123456789abcdefABCDEF" for char in digest)
            )
            if state == "disabled":
                inventory_status, last_status, last_checked = "disabled", "disabled", None
            elif not _native_onion_seed_route_proven(crawler, url):
                inventory_status, last_status, last_checked = "candidate", "tor_route_unverified", None
            elif state == "checked" and not digest_valid:
                inventory_status, last_status, last_checked = "candidate", "content_digest_missing", None
            else:
                inventory_status = state if state in {"checked", "failed"} else "candidate"
                last_status = state
                last_checked = datetime.now(UTC).isoformat() if state in {"checked", "failed"} else None
            row = {
                "url": url,
                "hostname": hostname,
                "seed_origin": crawler.seed_origin.get(url, "configured"),
                "discovered_from": crawler.discovered_from.get(url),
                "status": inventory_status,
                "last_status": last_status,
                "last_checked": last_checked,
            }
            # Keep a response digest as probe evidence only after route and content
            # checks are established; otherwise it could be misread as verified.
            if route_proven and digest_valid:
                row["last_response_sha256"] = digest.lower()
            rows.append(row)
        if not rows:
            return
        async def _do():
            client = await supabase._ensure()
            return await client.table("dw_onion_seeds").upsert(rows, on_conflict="url").execute()
        await supabase._retry(_do, attempts=2)

    async def _persist_native_onion_evidence(
        self,
        finding,
        *,
        tenant_id: str,
        watchlist_id: str,
        service_request_id: str,
        expected_attempt: int,
        metadata: dict,
    ) -> dict | None:
        """Persist a sanitized native-onion content match before finding success."""
        if finding.source_id != "native_onion" or metadata.get("target_match_in_content") is not True:
            return None
        excerpt = getattr(finding, "evidence_excerpt", None)
        if not excerpt:
            raise RuntimeError("native_onion_matched_content_without_safe_evidence_excerpt")
        if not finding.source_url:
            raise RuntimeError("native_onion_matched_content_without_source_url")
        result = await record_target_matched_onion_evidence(
            supabase,
            tenant_id=tenant_id,
            watchlist_id=watchlist_id,
            service_request_id=service_request_id,
            expected_attempt=expected_attempt,
            source_url=finding.source_url,
            sanitized_page_text=excerpt,
            observed_at=str(metadata.get("observed_at") or datetime.now(UTC).isoformat()),
        )
        metadata["durable_evidence"] = {
            "content_uri": result["content_uri"],
            "content_sha256": result["content_sha256"],
            "readback_sha256_verified": result["readback_sha256_verified"],
            "classification": result["finding_class"],
        }
        return result

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

        # Exact retro-sweep only; historical and future-dated feed records are
        # review-only and must never be silently promoted to current alerts.
        historical = await supabase.select(
            "dw_findings",
            "id,source_id,content_hash,kind,matched_value,context,source_url,severity,first_seen,collected_at,tenant_id,watchlist_id,source_metadata,finding_class",
            tenant_id=tenant_id,
        )
        exact = [f for f in historical if _finding_matches_target(f, watch_kind, watch_value)]
        historical_candidates = [
            {
                "id": item.get("id"), "source": item.get("source_id"),
                "collected_at": item.get("collected_at") or item.get("first_seen"),
                "content_hash": item.get("content_hash"), "source_url": item.get("source_url"),
                "severity": item.get("severity"),
                "temporal_class": (
                    item.get("source_metadata", {}).get("temporal_class")
                    if isinstance(item.get("source_metadata"), dict) else "historical_archive"
                ),
                "label": "historical match — review; not checked during this request",
            }
            for item in exact
        ]
        source_rows = await supabase.select("dw_sources", "id,enabled,last_status,last_pull_at")
        registered_source_ids = {str(x["id"]) for x in source_rows}
        enabled = {str(x["id"]) for x in source_rows if x.get("enabled") is True}
        sources: list[dict] = []
        pulled = []
        findings = []
        telegram_channels = configured_telegram_channels(use_defaults=False)
        async def run_source(source_id: str, pull, timeout: int, unavailable_reason: str | None = None):
            # Enforce the canonical source catalog at execution time. A provider
            # cannot run or be reported as coverage if it is excluded, unknown,
            # planned, or historical-only, even if an old DB registry row exists.
            definition = get_source(source_id)
            if definition is None or is_excluded_source(source_id):
                return {"source": source_id, "state": "unavailable", "reason": "excluded_by_policy"}, []
            if definition.availability == "historical_only":
                return {"source": source_id, "state": "historical_only", "reason": "historical_only_archived_feed"}, []
            if definition.availability != "implemented":
                return {"source": source_id, "state": "unavailable", "reason": definition.availability}, []
            # Before the native-source migration exists, reviewed environment seeds
            # can drive the collector. Once registered, an operator-disabled row
            # must be honored exactly like every other source.
            if not _source_is_enabled(source_id, enabled, registered_source_ids):
                return {"source": source_id, "state": "unavailable", "reason": "disabled"}, []
            if unavailable_reason:
                return {"source": source_id, "state": "unavailable", "reason": unavailable_reason}, []
            if pull is None:
                return {"source": source_id, "state": "unavailable", "reason": "unsupported_target_type"}, []
            try:
                findings = await asyncio.wait_for(pull(), timeout=timeout)
                monitor = source_monitors.get(source_id) or getattr(pull, "__self__", None)
                if source_id == "native_onion":
                    monitor = onion_crawler
                    try:
                        await self._persist_onion_seed_state(onion_crawler)
                        monitor.seed_state_persistence = "persisted"
                    except Exception:
                        # Preserve request-level results while exposing that the
                        # optional discovered-seed registry could not be updated.
                        monitor.seed_state_persistence = "unavailable"
                        logger.warning("onion seed registry persistence unavailable request_id=%s", request_id, exc_info=True)
                    proof_reason, missing_route_proof, missing_content_proof = _native_onion_unavailability(monitor)
                    inspected_pages = int(getattr(monitor, "pages_checked", 0) or 0)
                    if proof_reason:
                        # HTTP reachability is not proof that this response used
                        # a verified Tor circuit to a fetched v3 hidden service.
                        # Never persist matches or count pages as dark-web checked
                        # until protocol proof and inspected-content proof are present.
                        return {
                            "source": source_id,
                            "state": "unavailable",
                            "reason": proof_reason,
                            "route_proof_missing": missing_route_proof,
                            "content_proof_missing": missing_content_proof,
                            "unverified_page_responses": inspected_pages,
                            "seed_state_persistence": getattr(monitor, "seed_state_persistence", "not_attempted"),
                            "tor_control_authenticated": getattr(monitor, "tor_control_authenticated", False) is True,
                            "tor_bootstrap_complete": getattr(monitor, "tor_bootstrap_complete", False) is True,
                            "tor_version": getattr(monitor, "tor_version", None),
                            "tor_protocol_evidence": _native_onion_protocol_evidence(monitor),
                            **_native_onion_route_proof_state(monitor),
                        }, []
                if source_id == "ransomwatch":
                    if not getattr(monitor, "feed_checked", False):
                        return {
                            "source": source_id, "state": "unavailable",
                            "reason": "public_feed_not_confirmed",
                            "items_inspected": 0,
                        }, []
                    return {
                        "source": source_id,
                        "state": "checked",
                        "coverage": "current_feed_plus_historical_records",
                        "feed_observed_at": getattr(monitor, "feed_observed_at", None),
                        "content_sha256": getattr(monitor, "feed_content_sha256", None),
                        "feed_entries": getattr(monitor, "feed_entries_count", 0),
                        "posts_inspected": getattr(monitor, "posts_checked", 0),
                        "items_inspected": getattr(monitor, "posts_checked", 0),
                        "current_feed_entries": getattr(monitor, "current_post_count", 0),
                        "historical_entries": getattr(monitor, "historical_post_count", 0),
                        "future_dated_entries": getattr(monitor, "future_dated_post_count", 0),
                        "direct_onion_access_verified": False,
                    }, findings
                if source_id == "pastebin_public" and not getattr(monitor, "feed_checked", False):
                    return {
                        "source": source_id, "state": "unavailable",
                        "reason": "public_feed_not_confirmed", "items_checked": 0,
                    }, []
                if source_id == "pastebin_public" and getattr(monitor, "items_checked", 0) == 0:
                    return {
                        "source": source_id, "state": "unavailable", "coverage": "none",
                        "reason": "feed_checked_no_documents_inspected",
                        "feed_entries": getattr(monitor, "feed_entries_count", 0),
                        "items_checked": 0,
                        "items_inspected": 0,
                    }, []
                channel_status = getattr(monitor, "channel_status", {})
                failed_channels = [
                    channel for channel, state in channel_status.items()
                    if state != "checked"
                ]
                if channel_status:
                    successful_channels = [channel for channel, state in channel_status.items() if state == "checked"]
                    if not successful_channels:
                        return {
                            "source": source_id, "state": "failed",
                            "reason": "all_configured_channels_failed",
                            "items_inspected": 0,
                            "channels": [{"channel": channel, "state": state} for channel, state in sorted(channel_status.items())],
                        }, []
                    return {
                        "source": source_id,
                        "state": "checked",
                        "coverage": "partial" if failed_channels else "all_configured_channels_checked",
                        "checked_channels": len(successful_channels),
                        "failed_channels": len(failed_channels),
                        # Each successful public channel preview was fetched and inspected.
                        "items_inspected": len(successful_channels),
                        "channels": [
                            {"channel": channel, "state": state}
                            for channel, state in sorted(channel_status.items())
                        ],
                    }, findings
                seed_status = getattr(monitor, "seed_status", {})
                pages_checked = getattr(monitor, "pages_checked", None)
                pages_failed = getattr(monitor, "pages_failed", None)
                if pages_checked is not None:
                    successful_seeds = [seed for seed, state in seed_status.items() if state == "checked"]
                    failed_seeds = [seed for seed, state in seed_status.items() if state != "checked"]
                    if not successful_seeds and (failed_seeds or pages_failed):
                        return {
                            "source": source_id, "state": "failed",
                            "reason": "all_onion_seeds_unreachable",
                            "configured_seeds": getattr(monitor, "configured_seed_count", len(seed_status)),
                            "discovered_seeds": len(getattr(monitor, "discovered_seeds", [])),
                            "seeds": [{"seed": seed, "state": state, "origin": monitor.seed_origin.get(seed, "configured")} for seed, state in sorted(seed_status.items())],
                            "pages_checked": pages_checked, "pages_failed": pages_failed,
                        }, []
                    return {
                        "source": source_id,
                        "state": "checked",
                        "coverage": "partial" if failed_seeds or pages_failed else "all_reachable_pages_checked",
                        "configured_seeds": getattr(monitor, "configured_seed_count", len(seed_status)),
                        "discovered_seeds": len(getattr(monitor, "discovered_seeds", [])),
                        "seeds": [{"seed": seed, "state": state, "origin": monitor.seed_origin.get(seed, "configured")} for seed, state in sorted(seed_status.items())],
                        "pages_checked": pages_checked,
                        "pages_failed": pages_failed,
                        "seed_state_persistence": getattr(monitor, "seed_state_persistence", "not_attempted"),
                        "matches": getattr(monitor, "matches", 0),
                        "content_sha256": _native_onion_content_sha256(monitor),
                        "tor_control_status": getattr(monitor, "tor_control_status", "disabled"),
                        "tor_control_authenticated": getattr(monitor, "tor_control_authenticated", False) is True,
                        "tor_bootstrap_complete": getattr(monitor, "tor_bootstrap_complete", False) is True,
                        "tor_version": getattr(monitor, "tor_version", None),
                        "tor_protocol_evidence": _native_onion_protocol_evidence(monitor),
                        **_native_onion_route_proof_state(monitor),
                    }, findings
                if source_id == "pastebin_public":
                    return {
                        "source": source_id, "state": "checked",
                        "coverage": "all_returned_documents_fetched",
                        "feed_entries": getattr(monitor, "feed_entries_count", 0),
                        "items_checked": getattr(monitor, "items_checked", 0),
                        "items_inspected": getattr(monitor, "items_checked", 0),
                    }, findings
                if source_id == "bluesky_public":
                    return {
                        "source": source_id, "state": "checked",
                        "coverage": "public_search_results_inspected",
                        "posts_checked": getattr(monitor, "posts_checked", 0),
                        "items_inspected": getattr(monitor, "posts_checked", 0),
                        "matches": len(findings),
                    }, findings
                return {"source": source_id, "state": "checked"}, findings
            except Exception:
                logger.warning("dark-web provider request failed source=%s request_id=%s", source_id, request_id, exc_info=True)
                monitor = source_monitors.get(source_id) or getattr(pull, "__self__", None)
                status = {"source": source_id, "state": "failed", "reason": "source_request_failed"}
                channel_status = getattr(monitor, "channel_status", {})
                if channel_status:
                    status["channels"] = [
                        {"channel": channel, "state": state}
                        for channel, state in sorted(channel_status.items())
                    ]
                    status["checked_channels"] = sum(state == "checked" for state in channel_status.values())
                    status["failed_channels"] = sum(state != "checked" for state in channel_status.values())
                seed_status = getattr(monitor, "seed_status", {})
                if seed_status:
                    status["seeds"] = [
                        {"seed": seed, "state": state, "origin": monitor.seed_origin.get(seed, "configured")}
                        for seed, state in sorted(seed_status.items())
                    ]
                    status["pages_checked"] = getattr(monitor, "pages_checked", 0)
                    status["pages_failed"] = getattr(monitor, "pages_failed", 0)
                return status, []

        # Ransomwatch is a live-polled public aggregator feed with three
        # separate temporal classes. It is not direct proof of onion-site access.
        ransom_reason = (
            None if target_type in {"domain", "url", "brand"}
            else "unsupported_target_type"
        )
        public_target_supported = target_type in {"domain", "url", "email"}
        paste_reason = None if public_target_supported else "unsupported_target_type"
        telegram_reason = (
            "unsupported_target_type" if not public_target_supported
            else ("missing_channels" if not telegram_channels else None)
        )
        telegram_monitor = TelegramPublicMonitor(telegram_channels) if telegram_channels else None
        paste_monitor = PastePublicMonitor()
        bluesky_monitor = BlueskyPublicMonitor()
        onion_seeds, onion_seed_origins, onion_seed_discovered_from = await self._onion_seed_urls()
        onion_reason = (
            "missing_onion_seeds" if not onion_seeds
            else ("unsupported_target_type" if target_type not in {"domain", "url", "email", "brand", "username", "ip", "other"} else None)
        )
        onion_crawler = NativeOnionCrawler(
            seeds=onion_seeds,
            seed_origins=onion_seed_origins,
            discovered_from=onion_seed_discovered_from,
            service_request_id=request_id,
        )
        source_monitors = {
            "telegram_public": telegram_monitor,
            "pastebin_public": paste_monitor,
            "bluesky_public": bluesky_monitor,
        }
        provider_specs = [
            ("native_onion", (lambda: onion_crawler.pull(watch_kind, watch_value)) if not onion_reason else None, 150, onion_reason),
            ("ransomwatch", RansomwatchPuller().pull if not ransom_reason else None, 35, ransom_reason),
            ("pastebin_public", (lambda: paste_monitor.pull(target_type, watch_value)) if public_target_supported else None, 50, paste_reason),
            ("telegram_public", (lambda: telegram_monitor.pull(target_type, watch_value)) if telegram_monitor and public_target_supported else None, 90, telegram_reason),
            ("bluesky_public", (lambda: bluesky_monitor.pull(target_type, watch_value))
             if target_type in {"domain", "url", "email", "brand", "username", "ip"} else None,
             20, None if target_type in {"domain", "url", "email", "brand", "username", "ip"} else "unsupported_target_type"),
            ("github_code", None, 20, None),
        ]
        provider_results = await asyncio.gather(*(
            run_source(source_id, pull, timeout, reason)
            for source_id, pull, timeout, reason in provider_specs
        ))

        # Keep the feed's three time classes distinct. Current dated records may
        # enter the current finding/alert path; historical records are review-only;
        # future-dated records are quarantined from alerts.
        future_dated_candidates = []
        feed_historical_candidates = []
        normalized_provider_results = []
        for status, batch in provider_results:
            if str(status.get("source") or "") != "ransomwatch":
                normalized_provider_results.append((status, batch))
                continue
            current_batch, historical_batch, future_batch = _partition_ransomwatch_findings(
                batch, watch_kind, watch_value
            )
            feed_historical_candidates.extend(historical_batch)
            future_dated_candidates.extend(future_batch)
            normalized_provider_results.append((status, current_batch))
        provider_results = normalized_provider_results
        historical_candidates = (feed_historical_candidates + historical_candidates)[:1000]

        sources = []
        for status, _ in provider_results:
            definition = get_source(str(status.get("source") or ""))
            if definition is not None:
                status = {
                    **status,
                    "layer": definition.layer,
                    "category": definition.category,
                    "access_mode": definition.access_mode,
                    "availability": definition.availability,
                }
            sources.append(status)
        # Persist every real provider attempt. Protocol/content proof fields remain false
        # unless the collector explicitly supplies verified evidence.
        for source in sources:
            state = str(source.get("state") or "failed").lower()
            attempt_status = {
                "checked": "ok",
                "disabled": "disabled",
                "historical_only": "historical_only",
                "unavailable": "unavailable",
                "failed": "failed",
                "timeout": "timeout",
            }.get(state, "failed")
            inspected_items = _source_inspected_items(source)
            reason = str(source.get("reason") or "")
            error_code = reason if reason and all(
                char.isalnum() or char in "_.:-" for char in reason
            ) and len(reason) <= 100 else None
            try:
                await supabase.rpc("record_dw_source_attempt", {
                    "p_source_id": str(source.get("source") or ""),
                    "p_status": attempt_status,
                    "p_content_sha256": source.get("content_sha256"),
                    "p_inspected_items": inspected_items,
                    "p_error_code": error_code,
                    "p_metadata": {
                        "request_id": str(request_id),
                        "coverage": str(source.get("coverage") or ""),
                        "availability": str(source.get("availability") or ""),
                        "layer": str(source.get("layer") or ""),
                        "category": str(source.get("category") or ""),
                        "tor_protocol_evidence": source.get("tor_protocol_evidence", {}),
                    },
                    "p_route_verified": source.get("route_verified") is True,
                    "p_hs_desc_content_received": source.get("hs_desc_content_received") is True,
                    "p_descriptor_fetched": source.get("descriptor_fetched") is True,
                    "p_rendezvous_hop_verified": source.get("rendezvous_hop_verified") is True,
                    "p_stream_circuit_bound": source.get("stream_circuit_bound") is True,
                    "p_auth_ok": source.get("tor_control_authenticated") is True,
                })
            except Exception as exc:
                logger.warning(
                    "unable to persist source attempt source=%s request_id=%s",
                    source.get("source"), request_id, exc_info=True,
                )
                raise RuntimeError("source_attempt_ledger_persistence_failed") from exc

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
                "historical_candidates": historical_candidates[:200],
                "historical_candidate_count": len(historical_candidates),
                "evidence": historical_candidates[:200],
                "alerts": [],
                "completed_at": datetime.now(UTC).isoformat(),
            }
            await self._complete(
                request, "failed", "blocked", failure_result, "no_source_checked"
            )
            return

        # Persist only exact target matches. The global feed itself is still
        # useful for retro-sweep but a company-name resemblance is never silently
        # promoted to a confirmed match.
        evidence = []
        persistence_failures = 0
        evidence.extend(historical_candidates[:200])
        for finding in pulled[:2000]:
            if not _finding_matches_target(finding, watch_kind, watch_value):
                continue
            meta = dict(finding.metadata or {})
            meta["customer_match"] = "exact"
            meta["service_request_id"] = request_id
            tenant_hash = hashlib.sha256(f"{getattr(finding, 'source_id', '')}:{hashlib.sha256((str(finding.matched_value).strip().lower()).encode()).hexdigest()}:{watch_id}".encode()).hexdigest()
            trust_evidence = None
            try:
                trust_evidence = await self._persist_native_onion_evidence(
                    finding,
                    tenant_id=tenant_id,
                    watchlist_id=watch_id,
                    service_request_id=request_id,
                    expected_attempt=int(request["attempts"]),
                    metadata=meta,
                )
                recorded = await supabase.rpc("record_dw_finding", {
                    "p_source_id": finding.source_id, "p_content_hash": tenant_hash,
                    "p_kind": finding.kind, "p_matched_value": str(finding.matched_value).strip().lower(),
                    "p_context": finding.context, "p_severity": finding.severity,
                    "p_source_url": finding.source_url, "p_metadata": meta,
                    "p_tenant_id": tenant_id, "p_watchlist_id": watch_id,
                })
                _require_recorded_finding(recorded)
                evidence.append({
                    "source": finding.source_id,
                    "collected_at": datetime.now(UTC).isoformat(),
                    "content_hash": tenant_hash,
                    "source_url": finding.source_url,
                    **({
                        "trust_evidence_uri": trust_evidence["content_uri"],
                        "trust_evidence_sha256": trust_evidence["content_sha256"],
                        "trust_evidence_readback_verified": True,
                    } if trust_evidence else {}),
                })
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
            "id,source_id,content_hash,matched_value,context,source_url,severity,first_seen,collected_at,watchlist_id,web_layer,access_mode,finding_class,source_metadata",
            tenant_id=tenant_id, watchlist_id=watch_id,
        )
        # Keep archived Ransomwatch and legacy/unclassified rows out of current
        # findings. A native-onion row is a current candidate only when this
        # request persisted its durable evidence; no row is promoted to verified.
        current_persisted = [
            item for item in persisted if _is_current_finding(item, request_id)
        ]
        # The watchlist may already have findings from the continuous scheduler.
        # Include only current-classified durable rows in the current evidence list.
        evidence_by_hash = {
            str(item.get("content_hash") or ""): item
            for item in evidence
            if item.get("content_hash")
        }
        for item in current_persisted:
            content_hash = str(item.get("content_hash") or "")
            if not content_hash:
                continue
            evidence_by_hash.setdefault(content_hash, {
                "source": item.get("source_id"),
                "collected_at": item.get("collected_at") or item.get("first_seen"),
                "content_hash": content_hash,
                "source_url": item.get("source_url"),
                "label": "possible match — review",
            })
        evidence = list(evidence_by_hash.values())
        alerts = await supabase.select(
            "dw_alerts",
            "id,title,summary,severity,status,finding_id,created_at,case_id",
            tenant_id=tenant_id,
        )
        relevant_alerts = [a for a in alerts if str(a.get("finding_id")) in {str(f["id"]) for f in current_persisted}]
        case_id = None
        if relevant_alerts:
            # Reuse a case already linked to this request if a worker retry occurs.
            existing_link = await supabase.select_one(
                "customer_case_links", "case_id", service_request_id=request_id,
            )
            if existing_link:
                case_id = str(existing_link["case_id"])
            else:
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
                # customer_case_links.created_by is NOT NULL in production.
                # The authenticated request owner is carried by the claimed request;
                # fail closed rather than inserting a NULL actor or inventing one.
                await supabase.insert_one("customer_case_links", {
                    "organization_id": organization_id,
                    "service_request_id": request_id,
                    "case_id": case_id,
                    "created_by": _requester_actor(request),
                })
            for alert in relevant_alerts:
                if not alert.get("case_id"):
                    await supabase.update("dw_alerts", {"case_id": case_id}, id=str(alert["id"]), tenant_id=tenant_id)
        checked_sources = [x for x in sources if x["state"] == "checked"]
        unavailable_sources = [x for x in sources if x["state"] != "checked"]
        # Coverage describes this configured provider set only; it never claims
        # visibility into the entire dark web or unconfigured services.
        coverage = _coverage_state(sources)
        dark_sources = [x for x in sources if x.get("layer") == "dark"]
        surface_sources = [x for x in sources if x.get("layer") == "surface"]
        breach_intel_sources = [x for x in sources if x.get("layer") == "breach_intel"]
        dark_findings = [f for f in current_persisted if str(f.get("source_id") or "") == "native_onion"]
        surface_findings = [
            f for f in current_persisted
            if str(f.get("source_id") or "") not in {"native_onion", "ransomwatch"}
        ]
        breach_intel_findings = [
            f for f in current_persisted if str(f.get("source_id") or "") == "ransomwatch"
        ]
        native_status = next((x for x in dark_sources if x.get("source") == "native_onion"), None)
        result = {
            "service": "dark_web_monitoring", "target": watch_value, "target_type": target_type,
            "coverage": coverage, "sources_checked": checked_sources,
            "sources_unavailable": unavailable_sources,
            "dark_web": {
                "coverage": native_status.get("coverage", "unavailable") if native_status and native_status.get("state") == "checked" else "unavailable",
                "source": native_status or {"source": "native_onion", "state": "unavailable", "reason": "not_checked"},
                "findings": dark_findings[:200],
            },
            "surface_web": {"sources": surface_sources, "findings": surface_findings[:200]},
            "breach_intelligence": {
                "sources": breach_intel_sources,
                "findings": breach_intel_findings[:200],
                "historical_candidates": [
                    item for item in historical_candidates
                    if item.get("source") == "ransomwatch"
                ][:200],
                "future_dated_candidates": future_dated_candidates[:200],
                "temporal_summary": next((
                    {
                        "feed_observed_at": source.get("feed_observed_at"),
                        "feed_entries": source.get("feed_entries", 0),
                        "current_feed_entries": source.get("current_feed_entries", 0),
                        "historical_entries": source.get("historical_entries", 0),
                        "future_dated_entries": source.get("future_dated_entries", 0),
                    }
                    for source in sources if source.get("source") == "ransomwatch"
                ), {"state": "unavailable"}),
            },
            "source_summary": {
                "checked_count": len(checked_sources),
                "unavailable_count": len(unavailable_sources),
                "checked_source_ids": [x.get("source") for x in checked_sources],
                "unavailable_source_ids": [x.get("source") for x in unavailable_sources],
                "layers": {
                    "dark_web": dark_sources,
                    "surface_web": surface_sources,
                    "breach_intelligence": breach_intel_sources,
                },
            },
            "findings": current_persisted[:200],
            "historical_candidates": historical_candidates[:200],
            "historical_candidate_count": len(historical_candidates),
            "future_dated_candidates": future_dated_candidates[:200],
            "future_dated_candidate_count": len(future_dated_candidates),
            "ransomwatch_temporal_summary": next((
                {
                    "feed_observed_at": source.get("feed_observed_at"),
                    "feed_entries": source.get("feed_entries", 0),
                    "current_feed_entries": source.get("current_feed_entries", 0),
                    "historical_entries": source.get("historical_entries", 0),
                    "future_dated_entries": source.get("future_dated_entries", 0),
                    "direct_onion_access_verified": False,
                }
                for source in sources if source.get("source") == "ransomwatch"
            ), {"state": "unavailable"}),
            "evidence": evidence[:200], "alerts": relevant_alerts[:200],
            "case_id": case_id, "recommendations": (
                ["Review each possible match against the source evidence.", "Rotate exposed credentials and investigate affected accounts."]
                if persisted else ["No exact matches were confirmed in the sources checked.",
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
