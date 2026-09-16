from __future__ import annotations

"""Evidence-grade public web page acquisition for brand impersonation analysis.

The scanner intentionally fetches only public HTTP(S) endpoints, rejects local/private
network destinations, limits response sizes, and records cryptographic evidence for
every artifact it accepts. It does not execute page JavaScript.
"""

import asyncio
import hashlib
import ipaddress
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


_MAX_HTML_BYTES = 2_000_000
_MAX_IMAGE_BYTES = 5_000_000
_TIMEOUT_SECONDS = 12
_USER_AGENT = "Sentinel-BrandProtection/1.0 (+public-threat-research)"


@dataclass(frozen=True, slots=True)
class ImageCandidate:
    url: str
    relation: str
    alt: str | None = None


@dataclass(frozen=True, slots=True)
class PageArtifact:
    requested_url: str
    final_url: str
    status_code: int
    content_type: str
    fetched_at: datetime
    html_sha256: str
    title: str | None
    images: tuple[ImageCandidate, ...]


@dataclass(frozen=True, slots=True)
class ImageArtifact:
    url: str
    source_page: str
    content_type: str
    sha256: str
    bytes_size: int
    body: bytes


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title: str | None = None
        self._in_title = False
        self._title_parts: list[str] = []
        self.images: list[ImageCandidate] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {k.lower(): v for k, v in attrs}
        tag = tag.lower()
        if tag == "title":
            self._in_title = True
            return
        if tag == "img" and values.get("src"):
            self.images.append(ImageCandidate(values["src"] or "", "img", values.get("alt")))
        elif tag == "link" and values.get("href"):
            rel = (values.get("rel") or "").lower()
            if any(x in rel for x in ("icon", "apple-touch-icon")):
                self.images.append(ImageCandidate(values["href"] or "", rel))
        elif tag == "meta":
            prop = (values.get("property") or values.get("name") or "").lower()
            if prop in {"og:image", "twitter:image", "twitter:image:src"} and values.get("content"):
                self.images.append(ImageCandidate(values["content"] or "", prop))

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False
            self.title = " ".join("".join(self._title_parts).split())[:512] or None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)


def _assert_public_http_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("only absolute HTTP(S) URLs are supported")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are rejected")
    if parsed.port not in (None, 80, 443):
        raise ValueError("non-standard ports are rejected")
    host = parsed.hostname.rstrip(".").lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        raise ValueError("local hostnames are rejected")
    try:
        addresses = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
            addresses = {ipaddress.ip_address(info[4][0]) for info in infos}
        except OSError as exc:
            raise ValueError(f"unable to resolve destination: {host}") from exc
    for address in addresses:
        if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_multicast or address.is_unspecified:
            raise ValueError("private or non-public destination rejected")


def _read_limited(response, limit: int) -> bytes:
    data = bytearray()
    while len(data) <= limit:
        chunk = response.read(min(64 * 1024, limit + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    if len(data) > limit:
        raise ValueError("response exceeds configured size limit")
    return bytes(data)


def _fetch(url: str, limit: int) -> tuple[str, int, str, bytes]:
    _assert_public_http_url(url)
    request = Request(url, headers={"User-Agent": _USER_AGENT, "Accept": "text/html,image/avif,image/webp,image/png,image/jpeg,image/x-icon,*/*;q=0.5"})
    with urlopen(request, timeout=_TIMEOUT_SECONDS, follow_redirects=True) as response:  # noqa: S310 - URL is validated above
        final_url = response.geturl()
        _assert_public_http_url(final_url)
        status = int(getattr(response, "status", 200))
        content_type = response.headers.get_content_type().lower()
        body = _read_limited(response, limit)
    return final_url, status, content_type, body


async def fetch_page(url: str) -> PageArtifact:
    final_url, status, content_type, body = await asyncio.to_thread(_fetch, url, _MAX_HTML_BYTES)
    if content_type not in {"text/html", "application/xhtml+xml"}:
        raise ValueError(f"target is not an HTML page: {content_type}")
    parser = _PageParser()
    parser.feed(body.decode("utf-8", errors="replace"))
    base = final_url
    candidates: list[ImageCandidate] = []
    seen: set[str] = set()
    for candidate in parser.images:
        absolute = urljoin(base, candidate.url)
        try:
            _assert_public_http_url(absolute)
        except ValueError:
            continue
        if absolute not in seen:
            seen.add(absolute)
            candidates.append(ImageCandidate(absolute, candidate.relation, candidate.alt))
    return PageArtifact(
        requested_url=url,
        final_url=final_url,
        status_code=status,
        content_type=content_type,
        fetched_at=datetime.now(timezone.utc),
        html_sha256=hashlib.sha256(body).hexdigest(),
        title=parser.title,
        images=tuple(candidates[:32]),
    )


async def fetch_image(url: str, source_page: str) -> ImageArtifact:
    final_url, _status, content_type, body = await asyncio.to_thread(_fetch, url, _MAX_IMAGE_BYTES)
    if not (content_type.startswith("image/") or content_type == "application/octet-stream"):
        raise ValueError(f"candidate is not an image: {content_type}")
    return ImageArtifact(
        url=final_url,
        source_page=source_page,
        content_type=content_type,
        sha256=hashlib.sha256(body).hexdigest(),
        bytes_size=len(body),
        body=body,
    )
