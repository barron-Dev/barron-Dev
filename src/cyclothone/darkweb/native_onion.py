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
from cyclothone.darkweb.tor_control import TorControlProofCollector

logger = logging.getLogger(__name__)
MAX_SEEDS = 50
MAX_PAGES_PER_SEED = 20
MAX_TOTAL_PAGES = 100
MAX_BODY_BYTES = 512_000
ONION_SUFFIX = ".onion"
ONION_V3_HOST = re.compile(r"^[a-z2-7]{56}\.onion$")


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
        if parsed.scheme not in {"http", "https"} or not ONION_V3_HOST.fullmatch(host):
            return None
        if parsed.username or parsed.password:
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
    normalized = normalize(target)
    if not normalized:
        raise ValueError("native_onion_empty_normalized_target")

    escaped = re.escape(normalized)
    if kind == "domain":
        # A hostname must not match a larger hostname or a hostname suffix.
        return re.compile(r"(?<![\w.-])" + escaped + r"(?![\w.-])", re.IGNORECASE)
    if kind == "email":
        return re.compile(r"(?<![\w@.+-])" + escaped + r"(?![\w@.+-])", re.IGNORECASE)
    if kind == "ip":
        return re.compile(r"(?<![0-9a-f:.])" + escaped + r"(?![0-9a-f:.])", re.IGNORECASE)
    if kind == "phone":
        return re.compile(r"(?<!\d)" + escaped + r"(?!\d)", re.IGNORECASE)
    if kind in {"username", "company_name", "executive_name", "wallet", "api_key_hash", "employee_id", "customer_id", "other"}:
        return re.compile(r"(?<!\w)" + escaped + r"(?!\w)", re.IGNORECASE)
    raise ValueError("native_onion_unsupported_target_kind")


def sanitize_target_matched_excerpt(
    page_text: str,
    pattern: re.Pattern[str],
    *,
    max_context_chars: int = 240,
    max_chars: int = 1200,
) -> str | None:
    """Return a small match-centered excerpt with common secret material redacted."""
    match = pattern.search(page_text)
    if not match:
        return None
    start = max(0, match.start() - max_context_chars)
    end = min(len(page_text), match.end() + max_context_chars)
    excerpt = page_text[start:end]
    relative_start = match.start() - start
    relative_end = match.end() - start
    sentinel = "ZZTARGETZZ"
    excerpt = excerpt[:relative_start] + sentinel + excerpt[relative_end:]

    # Remove private-key blocks, credential assignments, bearer/JWT material,
    # cloud access-key identifiers, email addresses, and long opaque tokens.
    excerpt = re.sub(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        "[redacted-private-key]",
        excerpt,
        flags=re.IGNORECASE | re.DOTALL,
    )
    excerpt = re.sub(
        r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|bearer)\s*[:=]\s*(?!ZZTARGETZZ)[^\s,;]+",
        r"\1=[redacted]",
        excerpt,
    )
    excerpt = re.sub(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "[redacted-jwt]", excerpt)
    excerpt = re.sub(r"\bAKIA[0-9A-Z]{16}\b", "[redacted-cloud-key]", excerpt)
    excerpt = re.sub(r"(?<!\w)[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?!\w)", "[redacted-email]", excerpt)
    excerpt = re.sub(r"\b[A-Za-z0-9_+/=-]{32,}\b", "[redacted-token]", excerpt)
    excerpt = " ".join(excerpt.split()).replace(sentinel, match.group(0))[:max_chars]
    if not pattern.search(excerpt):
        return None
    return excerpt


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
        service_request_id: str | None = None,
    ) -> None:
        self.service_request_id = str(service_request_id or "")
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
        # Filled only by a future Tor-control collector that can bind a circuit,
        # hidden-service descriptor events, and this response digest per seed.
        # HTTPX/SOCKS reachability alone never populates this proof map.
        self.seed_route_proofs: dict[str, dict] = {}
        self.tor_control_status = "disabled"
        self.tor_control_authenticated = False
        self.tor_bootstrap_complete = False
        self.tor_version: str | None = None
        self.seed_probe_evidence: dict[str, dict] = {}
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
        collector: TorControlProofCollector | None = None
        request_proxy = self.proxy
        try:
            if TorControlProofCollector.enabled_from_env() and not self.service_request_id:
                # Global scheduler ticks have no customer request fence. Do not
                # attach control events to an invented or empty request identity.
                self.tor_control_status = "unavailable_missing_request_context"
            elif TorControlProofCollector.enabled_from_env():
                try:
                    collector = TorControlProofCollector.from_env(self.service_request_id)
                    await asyncio.to_thread(collector.start)
                    self.tor_control_status = "authenticated" if collector.controller is not None else "failed"
                    self.tor_control_authenticated = collector.controller is not None
                    self.tor_bootstrap_complete = collector.bootstrapped
                    self.tor_version = collector.tor_version
                    # Per-request credentials force Tor's IsolateSOCKSAuth stream
                    # isolation and let the ControlPort event be bound to this crawl.
                    request_proxy = collector.proxy_for_request(self.proxy)
                except Exception as exc:
                    # ControlPort failure is not proof of a clean source. Allow
                    # bounded crawling to finish, but route proof remains absent.
                    if collector is not None:
                        try:
                            await asyncio.to_thread(collector.close)
                        except Exception:
                            pass
                    collector = None
                    request_proxy = self.proxy
                    self.tor_control_status = "unavailable"
                    logger.warning("Tor control protocol unavailable error=%s", type(exc).__name__)
            else:
                # Without explicit ControlPort configuration, no protocol proof is minted.
                self.tor_control_status = "disabled"
            async with httpx.AsyncClient(
                proxy=request_proxy,
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
                            if collector is not None and url == seed:
                                await asyncio.to_thread(collector.begin_seed, seed)
                            async with client.stream("GET", url) as response:
                                content_type = response.headers.get("content-type", "").lower()
                                if url == seed and seed not in self.seed_probe_evidence:
                                    self.seed_probe_evidence[seed] = {
                                        "http_status": response.status_code,
                                        "content_type": content_type[:200] or None,
                                        "response_bytes": 0,
                                        "response_sha256": None,
                                        "error_code": None if 200 <= response.status_code < 300 else f"http_status_{response.status_code}",
                                    }
                                if response.status_code < 200 or response.status_code >= 300:
                                    self.pages_failed += 1
                                    continue
                                if content_type and not any(kind in content_type for kind in ("text/html", "text/plain", "application/xhtml")):
                                    continue
                                chunks: list[bytes] = []
                                body_size = 0
                                oversized_body = False
                                async for chunk in response.aiter_bytes():
                                    if body_size + len(chunk) > MAX_BODY_BYTES:
                                        oversized_body = True
                                        break
                                    chunks.append(chunk)
                                    body_size += len(chunk)
                                if oversized_body:
                                    if url == seed:
                                        self.seed_probe_evidence[seed] = {
                                            "http_status": response.status_code,
                                            "content_type": content_type[:200] or None,
                                            "response_bytes": body_size,
                                            "response_sha256": None,
                                            "error_code": "response_body_too_large",
                                        }
                                    self.pages_failed += 1
                                    continue
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
                            if url == seed and collector is not None:
                                await asyncio.to_thread(collector.complete_seed_response, seed, body_hash)
                                self.seed_route_proofs[seed] = await asyncio.to_thread(
                                    collector.wait_for_proof,
                                    seed,
                                    body_hash,
                                    timeout_seconds=3.0,
                                )
                            if url == seed:
                                self.seed_probe_evidence[seed] = {
                                    "http_status": response.status_code,
                                    "content_type": content_type[:200] or None,
                                    "response_bytes": len(body),
                                    "response_sha256": body_hash,
                                    "error_code": None,
                                }
                            total_pages += 1
                            seed_pages += 1
                            self.pages_checked += 1
                            seed_success = True
                            content_match = pattern.search(page_text)
                            url_match = pattern.search(url)
                            # A target appearing only in a URL/path is not proof
                            # of exposure. Keep crawling metadata, but do not emit
                            # a customer finding without a body-content match.
                            if content_match:
                                self.matches += 1
                                evidence_excerpt = sanitize_target_matched_excerpt(page_text, pattern)
                                if not evidence_excerpt:
                                    raise RuntimeError("native_onion_matched_content_without_safe_excerpt")
                                findings.append(Finding(
                                    source_id=self.SOURCE,
                                    kind=target_kind,
                                    matched_value=normalize(target_value),
                                    context="Exact monitored identifier observed on a public onion page; bounded evidence excerpt is stored separately when safe.",
                                    severity="critical",
                                    source_url=url,
                                    metadata={
                                        "exposure_layer": "dark",
                                        "access_mode": "tor_public_onion",
                                        "match_method": "deterministic_exact_token",
                                        "target_match_in_content": bool(content_match),
                                        "target_match_in_url": bool(url_match),
                                        "seed_host": host,
                                        "crawl_depth": depth,
                                        "content_sha256": body_hash,
                                        "observed_at": datetime.now(UTC).isoformat(),
                                    },
                                    evidence_excerpt=evidence_excerpt,
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
                                    elif link_host not in scheduled_hosts and len(self.discovered_seeds) < MAX_SEEDS:
                                        # Inventory the link as a candidate; do not probe it in this run.
                                        scheduled_hosts.add(link_host)
                                        self.seed_origin[clean] = "discovered"
                                        self.discovered_from[clean] = url
                                        self.discovered_seeds.append({"url": clean, "discovered_from": url})
                        except asyncio.CancelledError:
                            raise
                        except Exception as exc:
                            if url == seed and seed not in self.seed_probe_evidence:
                                self.seed_probe_evidence[seed] = {
                                    "http_status": None,
                                    "content_type": None,
                                    "response_bytes": 0,
                                    "response_sha256": None,
                                    "error_code": type(exc).__name__[:120],
                                }
                            self.pages_failed += 1
                            logger.info("native onion page failed host=%s error=%s", host, type(exc).__name__)
                    self.seed_status[seed] = "checked" if seed_success else "failed"
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise RuntimeError(f"native_onion_collection_failed:{type(exc).__name__}") from exc
        finally:
            if collector is not None:
                await asyncio.to_thread(collector.close)
        if self.pages_checked == 0:
            raise RuntimeError("native_onion_no_seed_reachable")
        return findings
