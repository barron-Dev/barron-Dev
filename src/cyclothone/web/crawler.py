from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser

import httpx

logger = logging.getLogger(__name__)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
WALLET_RE = re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b")
CRED_PAIR_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}:[^\s<>&]{6,64}")


@dataclass(frozen=True, slots=True)
class WebPage:
    url: str
    content_hash: str
    status_code: int
    content_type: str
    body: bytes
    emails: tuple[str, ...]
    urls: tuple[str, ...]
    wallets: tuple[str, ...]
    credential_indicators: int


class RobotsCache:
    _cache: dict[str, RobotFileParser] = {}

    @classmethod
    async def allowed(cls, url: str, user_agent: str = "CyclothoneBot/1.0") -> bool:
        parts = urlsplit(url)
        root = f"{parts.scheme}://{parts.netloc}"
        parser = cls._cache.get(root)
        if parser is None:
            parser = RobotFileParser(urljoin(root, "/robots.txt"))
            try:
                async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
                    response = await client.get(parser.url, headers={"user-agent": user_agent})
                    if response.status_code >= 400:
                        return False
                    parser.parse(response.text.splitlines())
            except Exception:
                return False
            cls._cache[root] = parser
        return parser.can_fetch(user_agent, url)


class WebCrawler:
    """Bounded crawler for explicitly configured public/authorized targets.

    It never submits credentials, bypasses authentication, or stores credential
    values. Redirects are validated before following so a public URL cannot
    pivot the crawler into a private/link-local network. Onion targets require
    an explicitly configured Tor proxy.
    """

    USER_AGENT = "CyclothoneBot/1.0"

    def __init__(self, tor_proxy: str | None = None, max_bytes: int = 2 * 1024 * 1024) -> None:
        self.tor_proxy = tor_proxy
        self.max_bytes = max_bytes

    async def crawl(self, url: str, *, layer: str = "surface", respect_robots: bool = True, depth: int = 0) -> list[WebPage]:
        self._validate_target(url, layer)
        results: list[WebPage] = []
        queue: list[tuple[str, int]] = [(url, 0)]
        seen: set[str] = set()
        root_host = (urlsplit(url).hostname or "").lower()
        while queue:
            current, current_depth = queue.pop(0)
            if current in seen or current_depth > depth:
                continue
            seen.add(current)
            if respect_robots and layer != "dark" and not await RobotsCache.allowed(current, self.USER_AGENT):
                continue
            page = await self._fetch(current, layer, root_host=root_host)
            if page is None:
                continue
            results.append(page)
            if current_depth >= depth:
                continue
            for link in page.urls[:20]:
                parsed = urlsplit(link)
                if parsed.scheme not in {"http", "https"}:
                    continue
                if (parsed.hostname or "").lower() == root_host and link not in seen:
                    queue.append((link, current_depth + 1))
        return results

    @classmethod
    def _validate_target(cls, url: str, layer: str) -> None:
        if layer not in {"surface", "deep", "dark"}:
            raise ValueError("invalid exposure layer")
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("crawl target must be an HTTP(S) URL")
        host = parsed.hostname.lower().rstrip(".")
        if layer == "dark" and not host.endswith(".onion"):
            raise ValueError("dark-layer crawl targets must use an onion hostname")
        if host.endswith(".onion") and layer != "dark":
            raise ValueError("onion targets must be classified as dark")
        cls._reject_private_host(host)

    @staticmethod
    def _reject_private_host(host: str) -> None:
        try:
            addresses = {ipaddress.ip_address(host)}
        except ValueError:
            try:
                addresses = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
            except socket.gaierror as exc:
                raise ValueError("target hostname cannot be resolved") from exc
        for ip in addresses:
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                raise ValueError("private or non-public network targets are not permitted")

    async def _fetch(self, url: str, layer: str, *, root_host: str) -> WebPage | None:
        parsed = urlsplit(url)
        self._validate_target(url, layer)
        kwargs = {
            "timeout": 20.0,
            "follow_redirects": False,
            "headers": {"user-agent": self.USER_AGENT, "accept": "text/html,text/plain,application/json;q=0.9,*/*;q=0.1"},
        }
        if parsed.hostname and parsed.hostname.endswith(".onion"):
            if not self.tor_proxy:
                logger.warning("dark target skipped because no Tor proxy is configured")
                return None
            kwargs["proxy"] = self.tor_proxy
        try:
            async with httpx.AsyncClient(**kwargs) as client:
                response = await client.get(url)
                redirects = 0
                while response.status_code in {301, 302, 303, 307, 308} and redirects < 5:
                    location = response.headers.get("location")
                    if not location:
                        break
                    next_url = urljoin(str(response.url), location)
                    self._validate_target(next_url, layer)
                    next_host = (urlsplit(next_url).hostname or "").lower()
                    if next_host != root_host:
                        raise ValueError("cross-origin redirects are not permitted")
                    response = await client.get(next_url)
                    redirects += 1
                body = response.content[: self.max_bytes]
        except Exception as exc:
            logger.info("web fetch failed target=%s layer=%s error=%s", url, layer, type(exc).__name__)
            return None
        content_type = response.headers.get("content-type", "")
        text = body.decode("utf-8", errors="ignore")
        emails = tuple(dict.fromkeys(EMAIL_RE.findall(text)))[:200]
        urls = tuple(dict.fromkeys(URL_RE.findall(text)))[:200]
        wallets = tuple(dict.fromkeys(WALLET_RE.findall(text)))[:50]
        credentials = len(CRED_PAIR_RE.findall(text))
        # Preserve provenance via the original content hash, but never expose
        # recovered credential pairs through the WebPage body to downstream code.
        redacted_body = CRED_PAIR_RE.sub(lambda m: m.group(0).split(":", 1)[0] + ":[REDACTED]", text).encode("utf-8")
        return WebPage(
            url=str(response.url),
            content_hash=hashlib.sha256(body).hexdigest(),
            status_code=response.status_code,
            content_type=content_type[:120],
            body=redacted_body[: self.max_bytes],
            emails=emails,
            urls=urls,
            wallets=wallets,
            credential_indicators=credentials,
        )
