from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

import httpx

from cyclothone.storage.supabase_client import supabase

logger = logging.getLogger(__name__)

AHMIA_SEARCH_URL = "https://ahmia.fi/search/"
ONION_V3_HOST = re.compile(r"^[a-z2-7]{56}\.onion$", re.IGNORECASE)
MAX_CLAIM = 5
MAX_LEASE_SECONDS = 120
MAX_ATTEMPTS = 6
MAX_SEARCH_RESULTS = 25
MAX_INDEX_BODY = 1_000_000
ALLOWED_KINDS = {
    "official_criminal_justice_source_discovery",
    "official_corrections_prison_source_discovery",
    "public_cybercrime_advisory_source_discovery",
    "public_onion_threat_intel_candidate_discovery",
}
ALLOWED_CATEGORIES = {
    "criminal_justice_public_records",
    "corrections_prisons",
    "cybercrime_public_advisories",
    "onion_threat_intel_discovery",
}


def _candidate_onion_url(value: str) -> str | None:
    try:
        parsed = urlsplit(value.strip())
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme not in {"http", "https"} or not ONION_V3_HOST.fullmatch(host):
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        if parsed.port is not None and parsed.port not in {80, 443}:
            return None
        if parsed.query or parsed.fragment:
            return None
        return f"{parsed.scheme}://{host}{parsed.path or '/'}"
    except (ValueError, UnicodeError):
        return None


class _AhmiaLinks(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() != "a":
            return
        href = dict(attrs).get("href")
        if isinstance(href, str) and ".onion" in href.lower():
            self.links.append(href.strip())


def _search_term(scope_key: str, category_slug: str) -> str:
    # Search terms discover public index entries only; never imply attribution
    # or access private criminal forums, marketplaces, or stolen datasets.
    scope = re.sub(r"[^a-zA-Z0-9 -]", " ", scope_key).strip()[:80]
    category = category_slug.replace("_", " ")
    return f"{scope} {category} public information onion"


class DWDiscoveryQueueWorker:
    """Bounded public-index discovery worker using lease-fenced queue RPCs.

    It only records candidate onion URLs from Ahmia's public search index.
    It does not visit candidate onion hosts, ingest illicit datasets, or assert
    that a candidate is criminal, official, reachable, or relevant.
    """

    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._enabled = os.getenv("CYCLOTHONE_DW_DISCOVERY_WORKER_ENABLED", "false").strip().lower() not in {
            "0", "false", "no", "off"
        }

    def start(self) -> None:
        if not self._enabled:
            logger.info("DW discovery queue worker disabled by configuration")
            return
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._loop(), name="cyclothone-dw-discovery-queue")

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
        await asyncio.sleep(10)
        while not self._stop.is_set():
            try:
                rows = await supabase.rpc(
                    "claim_dw_source_discovery_jobs",
                    {"p_limit": MAX_CLAIM, "p_lease_seconds": MAX_LEASE_SECONDS},
                )
                if not isinstance(rows, list) or not rows:
                    await self._sleep(20)
                    continue
                await asyncio.gather(*(self._guarded(row) for row in rows if isinstance(row, dict)))
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Missing/unapplied migration is a visible blocker, never a fake success.
                logger.error("DW discovery queue unavailable error=%s", type(exc).__name__)
                await self._sleep(30)

    async def _sleep(self, seconds: int) -> None:
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            pass

    async def _guarded(self, job: dict) -> None:
        # The claim RPC exposes the queue primary key as job_id (not id).
        job_id = job.get("job_id")
        lease_token = job.get("lease_token")
        if job_id is None or not lease_token:
            logger.error("DW discovery claim missing fencing fields; refusing job")
            return
        try:
            outcome, metadata, error_code, retry_after = await self._process(job)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            outcome, metadata, error_code, retry_after = (
                "retry",
                {"worker_error_type": type(exc).__name__},
                "discovery_attempt_failed",
                300,
            )
        try:
            accepted = await supabase.rpc(
                "complete_dw_source_discovery_job",
                {
                    "p_job_id": job_id,
                    "p_lease_token": lease_token,
                    "p_outcome": outcome,
                    "p_error_code": error_code,
                    "p_result_metadata": metadata,
                    # SQL validates this argument even for completed/dead-letter outcomes.
                    "p_retry_after_seconds": max(30, min(86400, retry_after or 300)),
                    "p_max_attempts": MAX_ATTEMPTS,
                },
            )
            if accepted is not True and accepted != [True]:
                logger.warning("DW discovery completion fence rejected job_id=%s", job_id)
        except Exception as exc:
            logger.error("DW discovery completion unavailable job_id=%s error=%s", job_id, type(exc).__name__)

    async def _process(self, job: dict) -> tuple[str, dict, str | None, int]:
        kind = str(job.get("discovery_kind") or "")
        scope = str(job.get("scope_key") or "")
        category = str(job.get("category_slug") or "")
        if kind not in ALLOWED_KINDS or category not in ALLOWED_CATEGORIES or not scope:
            return "dead_letter", {"reason": "unsupported_discovery_job"}, "unsupported_discovery_job", 0

        if kind != "public_onion_threat_intel_candidate_discovery":
            # Official-source discovery is deliberately not guessed. It needs
            # curated regional adapters before a job can claim success.
            return "retry", {
                "reason": "official_source_adapter_not_integrated",
                "scope_key": scope,
                "category_slug": category,
            }, "provider_adapter_not_integrated", 3600

        term = _search_term(scope, category)
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(12.0, connect=8.0),
            follow_redirects=False,
            headers={"user-agent": "Cyclothone-DW-Discovery/1.0", "accept": "text/html"},
        ) as client:
            response = await client.get(AHMIA_SEARCH_URL, params={"q": term})
            if response.status_code != 200:
                return "retry", {
                    "index": "ahmia_public_search",
                    "http_status": response.status_code,
                    "candidate_count": 0,
                    "scope_key": scope,
                    "category_slug": category,
                }, "public_index_unavailable", 900
            body = response.content[:MAX_INDEX_BODY]
            if not body:
                return "retry", {"index": "ahmia_public_search", "candidate_count": 0}, "empty_index_response", 900
            parser = _AhmiaLinks()
            parser.feed(body.decode(response.encoding or "utf-8", errors="replace"))

        candidates: list[str] = []
        seen: set[str] = set()
        for href in parser.links:
            candidate = _candidate_onion_url(href)
            if candidate and candidate not in seen:
                seen.add(candidate)
                candidates.append(candidate)
            if len(candidates) >= MAX_SEARCH_RESULTS:
                break

        inserted = 0
        existing = 0
        for candidate in candidates:
            parsed = urlsplit(candidate)
            host = (parsed.hostname or "").lower()
            try:
                current = await supabase.select_one("dw_onion_seeds", "id,status", url=candidate)
                if current:
                    existing += 1
                    continue
                await supabase.insert_one("dw_onion_seeds", {
                    "url": candidate,
                    "hostname": host,
                    "seed_origin": "discovered",
                    "discovered_from": AHMIA_SEARCH_URL,
                    "status": "candidate",
                    "last_status": "candidate",
                    "category_slug": category,
                    "region_scope": scope,
                    "source_role": "public_index_candidate",
                    "provenance_url": AHMIA_SEARCH_URL,
                    "probe_metadata": {
                        "index": "ahmia_public_search",
                        "search_term_sha256": hashlib.sha256(term.encode()).hexdigest(),
                        "candidate_only": True,
                        "reachability_checked": False,
                        "content_inspected": False,
                        "criminality_attributed": False,
                    },
                    "candidate_trust": "unverified",
                })
                inserted += 1
            except Exception as exc:
                # A concurrent insert or schema mismatch is not a verified source.
                logger.info("DW onion candidate persistence skipped error=%s", type(exc).__name__)

        return "completed", {
            "index": "ahmia_public_search",
            "scope_key": scope,
            "category_slug": category,
            "search_term_sha256": hashlib.sha256(term.encode()).hexdigest(),
            "candidate_count": len(candidates),
            "inserted_candidate_count": inserted,
            "already_catalogued_count": existing,
            "candidates_are_unverified": True,
            "no_onion_hosts_probed": True,
            "no_page_content_inspected": True,
        }, None, 0
