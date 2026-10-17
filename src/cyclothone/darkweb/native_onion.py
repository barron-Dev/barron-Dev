from __future__ import annotations

import asyncio
import hashlib
import html
import logging
import os
import re
from datetime import UTC, datetime
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from cyclothone.darkweb.pullers import Finding, normalize

logger = logging.getLogger(__name__)
MAX_SEEDS = 50
MAX_PAGES_PER_SEED = 20
MAX_TOTAL_PAGES = 100
MAX_BODY_BYTES = 512_000
ONION_SUFFIX = ".onion"


def configured_onion_seeds() -> list[str]:
    """Return explicitly configured public onion URLs; never discover arbitrary hosts."""
    raw = os.getenv("CYCLOTHONE_DW_ONION_SEEDS", "")
    seeds: list[str] = []
    seen: set[str] = set()
    for value in raw.split(","):
        candidate = value.strip()
        if not candidate:
            continue
        parsed = _safe_onion_url(candidate)
        if not parsed:
            logger.warning("ignoring invalid native onion seed")
            continue
        normalized = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
        if normalized not in seen:
            seen.add(normalized)
            seeds.append(normalized)
        if len(seeds) >= MAX_SEEDS:
            break
    return seeds


def _safe_onion_url(value: str):
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme not in {"http", "https"} or not host.endswith(ONION_SUFFIX):
            return None
        if parsed.username or parsed.password or not host[:-len(ONION_SUFFIX)]:
            return None
        if parsed.port and parsed.port not in {80, 443}:
            return None
        if parsed.query or parsed.fragment:
            return None
        return parsed
    except ValueError:
        return None


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text_parts: list[str] = []
        self.links: list[str] = []
        self._in_script = False
        self._in_style = False

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.lower()
        if tag in {"script", "style", "noscript"}:
            self._in_script = tag in {"script", "noscript"}
            self._in_style = tag == "style"
        if tag == "a":
            href = dict(attrs).get("href")
            if isinstance(href, str) and href.strip():
                self.links.append(html.unescape(href.strip()))

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "noscript"}:
            self._in_script = False
        if tag.lower() == "style":
            self._in_style = False

    def handle_data(self, data: str) -> None:
        if not self._in_script and not self._in_style:
            cleaned = " ".join(data.split())
            if cleaned:
                self.text_parts.append(cleaned)


def _target_pattern(kind: str, target: str) -> re.Pattern[str]:
    escaped = re.escape(normalize(target))
    if kind in {"domain", "email", "username", "company_name", "ip"}:
        return re.compile(r"(?<![\w@.+-])" + escaped + r"(?![\w@.+-])", re.IGNORECASE)
    return re.compile(escaped, re.IGNORECASE)


class NativeOnionCrawler:
    """Bounded, deterministic crawler for explicitly configured public .onion pages.

    It stores no page bodies or credential material. A Tor SOCKS proxy is required
    for network access; no third-party intelligence API key is used.
    """

    SOURCE = "native_onion"

    def __init__(
        self,
        seeds: list[str] | None = None,
        proxy: str | None = None,
        seed_origins: dict[str, str] | None = None,
        discovered_from: dict[str, str] | None = None,
    ) -> None:
        self.seeds = list(dict.fromkeys(seeds if seeds is not None else configured_onion_seeds()))
        self.proxy = (proxy or os.getenv("CYCLOTHONE_DW_ONION_PROXY") or "socks5://127.0.0.1:9050").strip()
        self.seed_origin: dict[str, str] = {
            seed: (seed_origins or {}).get(seed, "configured") for seed in self.seeds
        }
        self.configured_seed_count = sum(origin == "configured" for origin in self.seed_origin.values())
        self.seed_status: dict[str, str] = {}
        self.discovered_from: dict[str, str] = dict(discovered_from or {})
        self.discovered_seeds: list[dict[str, str]] = []
        self.seed_content_hash: dict[str, str] = {}
        self.pages_checked = 0
        self.pages_failed = 0
        self.matches = 0

    async def pull(self, target_kind: str, target_value: str) -> list[Finding]:
        if not self.seeds:
            raise RuntimeError("native_onion_missing_seeds")
        if not self.proxy:
            raise RuntimeError("native_onion_missing_tor_proxy")
        pattern = _target_pattern(target_kind, target_value)
        findings: list[Finding] = []
        total_pages = 0
        timeout = httpx.Timeout(15.0, connect=20.0)
        limits = httpx.Limits(max_connections=5, max_keepalive_connections=2)
        try:
            async with httpx.AsyncClient(
                proxy=self.proxy,
                timeout=timeout,
                limits=limits,
                follow_redirects=False,
                headers={"user-agent": "Cyclothone-Native-DarkWeb/1.0", "accept": "text/html,text/plain;q=0.9"},
            ) as client:
                roots = list(self.seeds)
                scheduled_hosts = {
                    (parsed.hostname or "").lower()
                    for value in roots
                    if (parsed := _safe_onion_url(value)) is not None
                }
                root_index = 0
                while root_index < len(roots):
                    seed = roots[root_index]
                    root_index += 1
                    if total_pages >= MAX_TOTAL_PAGES:
                        self.seed_status[seed] = "not_checked_budget"
                        continue
                    parsed_seed = _safe_onion_url(seed)
                    if not parsed_seed:
                        self.seed_status[seed] = "invalid_seed"
                        continue
                    host = (parsed_seed.hostname or "").lower()
                    queue: list[tuple[str, int]] = [(seed, 0)]
                    visited: set[str] = set()
                    seed_pages = 0
                    seed_success = False
                    while queue and seed_pages < MAX_PAGES_PER_SEED and total_pages < MAX_TOTAL_PAGES:
                        url, depth = queue.pop(0)
                        if url in visited:
                            continue
                        visited.add(url)
                        try:
                            async with client.stream("GET", url) as response:
                                if response.status_code < 200 or response.status_code >= 300:
                                    self.pages_failed += 1
                                    continue
                                content_type = response.headers.get("content-type", "").lower()
                                if content_type and not any(kind in content_type for kind in ("text/html", "text/plain", "application/xhtml")):
                                    continue
                                chunks: list[bytes] = []
                                body_size = 0
                                async for chunk in response.aiter_bytes():
                                    remaining = MAX_BODY_BYTES - body_size
                                    if remaining <= 0:
                                        break
                                    chunks.append(chunk[:remaining])
                                    body_size += min(len(chunk), remaining)
                                    if body_size >= MAX_BODY_BYTES:
                                        break
                                body = b"".join(chunks)
                                text = body.decode(response.encoding or "utf-8", errors="replace")
                            if not body.strip():
                                self.pages_failed += 1
                                continue
                            parser = _PageParser()
                            parser.feed(text)
                            page_text = " ".join(parser.text_parts)
                            if not page_text and not parser.links:
                                self.pages_failed += 1
                                continue
                            body_hash = hashlib.sha256(body).hexdigest()
                            self.seed_content_hash.setdefault(seed, body_hash)
                            total_pages += 1
                            seed_pages += 1
                            self.pages_checked += 1
                            seed_success = True
                            if pattern.search(page_text) or pattern.search(url):
                                self.matches += 1
                                findings.append(Finding(
                                    source_id=self.SOURCE,
                                    kind=target_kind,
                                    matched_value=normalize(target_value),
                                    context="Exact monitored identifier observed on a public onion page; page contents were not retained.",
                                    severity="critical",
                                    source_url=url,
                                    metadata={
                                        "exposure_layer": "dark",
                                        "access_mode": "tor_public_onion",
                                        "match_method": "deterministic_exact_token",
                                        "seed_host": host,
                                        "crawl_depth": depth,
                                        "content_sha256": body_hash,
                                        "observed_at": datetime.now(UTC).isoformat(),
                                    },
                                ))
                            if depth < 1:
                                for href in parser.links:
                                    absolute = urljoin(url, href)
                                    parsed = _safe_onion_url(absolute)
                                    if not parsed:
                                        continue
                                    link_host = (parsed.hostname or "").lower()
                                    clean = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
                                    if link_host == host:
                                        if clean not in visited and len(queue) < MAX_PAGES_PER_SEED:
                                            queue.append((clean, depth + 1))
                                    elif link_host not in scheduled_hosts and len(roots) < MAX_SEEDS:
                                        # Discover only public onion links; never follow clearnet hosts.
                                        scheduled_hosts.add(link_host)
                                        roots.append(clean)
                                        self.seed_origin[clean] = "discovered"
                                        self.discovered_from[clean] = url
                                        self.discovered_seeds.append({"url": clean, "discovered_from": url})
                        except asyncio.CancelledError:
                            raise
                        except Exception as exc:
                            self.pages_failed += 1
                            logger.info("native onion page failed host=%s error=%s", host, type(exc).__name__)
                    self.seed_status[seed] = "checked" if seed_success else "failed"
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise RuntimeError(f"native_onion_collection_failed:{type(exc).__name__}") from exc
        if self.pages_checked == 0:
            raise RuntimeError("native_onion_no_seed_reachable")
        return findings
