from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from datetime import UTC, datetime
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger(__name__)
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


@dataclass(frozen=True, slots=True)
class Finding:
    source_id: str
    kind: str
    matched_value: str
    context: str | None
    severity: str
    source_url: str | None
    metadata: dict
    # Bounded, sanitized content excerpt kept out of general-purpose metadata.
    evidence_excerpt: str | None = None


def normalize(value: str) -> str:
    return value.strip().lower()


def value_hash(value: str) -> str:
    return hashlib.sha256(normalize(value).encode()).hexdigest()


def _redact(text: str) -> str:
    # Never retain password material from credential-pair matches.
    return EMAIL_RE.sub("[email]", text)[:2000]


def _domain_from_victim_title(title: str) -> str | None:
    """Return a domain only when the victim title itself is exactly a hostname/URL.

    Ransomwatch's post_url identifies the leak-site post, not the victim's domain.
    Treating that URL's host as the victim domain would create false attribution.
    """
    candidate = title.strip().strip(".,;:()[]{}")
    if not candidate or any(char.isspace() for char in candidate):
        return None
    parsed = urlsplit(candidate if "://" in candidate else f"https://{candidate}")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or "." not in host:
        return None
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
        return None
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        return None
    if "://" not in candidate and candidate.lower().rstrip(".") != host:
        return None
    if host in {"localhost", "localhost.localdomain"} or host.endswith((".local", ".internal", ".test", ".invalid")):
        return None
    return host


class RansomwatchPuller:
    """Inspect the current public Ransomwatch feed while preserving temporal classes.

    This is an aggregator feed, not proof of direct live Tor access to a leak site.
    Fresh, dated feed entries may appear as current feed intelligence; older or
    undated entries remain historical, and future-dated entries are flagged.
    """
    SOURCE = "ransomwatch"
    FEED = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
    # "Current" means a recent, timestamped aggregator-feed observation,
    # not a direct live onion check. Keep this distinct from source availability.
    CURRENT_WINDOW_DAYS = 30
    FUTURE_CLOCK_SKEW_SECONDS = 300
    MAX_FEED_BYTES = 10_000_000
    MAX_FEED_ENTRIES = 5000

    def __init__(self) -> None:
        self.feed_checked = False
        self.feed_observed_at: str | None = None
        self.feed_content_sha256: str | None = None
        self.feed_entries_count = 0
        self.posts_checked = 0
        self.current_post_count = 0
        self.historical_post_count = 0
        self.future_dated_post_count = 0
        # Bounded metadata-only ledger for all dated/undated feed entries. It
        # contains no page bodies and can be reconciled with tenant matches.
        self.temporal_records: list[dict] = []
        self.temporal_records: list[dict] = []

    @classmethod
    def _classify_published(cls, value: object, observed_at: datetime) -> tuple[str, str | None]:
        raw = str(value or "").strip()
        if not raw:
            return "historical_archive", None
        parsed: datetime | None = None
        candidate = raw.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%m/%d/%Y"):
                try:
                    parsed = datetime.strptime(raw, fmt)
                    break
                except ValueError:
                    continue
        if parsed is None:
            return "historical_archive", None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        parsed = parsed.astimezone(UTC)
        age_seconds = (observed_at - parsed).total_seconds()
        if age_seconds < -cls.FUTURE_CLOCK_SKEW_SECONDS:
            return "future_dated", parsed.isoformat()
        # Small publisher/collector clock skew is tolerated, but only inside
        # the explicit five-minute window. The customer alert guard uses the
        # same bound, so near-future timestamps are not silently archived.
        if -cls.FUTURE_CLOCK_SKEW_SECONDS <= age_seconds <= cls.CURRENT_WINDOW_DAYS * 86400:
            return "current_feed", parsed.isoformat()
        return "historical_archive", parsed.isoformat()

    async def pull(self) -> list[Finding]:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(self.FEED)
                response.raise_for_status()
                if len(response.content) > self.MAX_FEED_BYTES:
                    raise RuntimeError("Ransomwatch feed exceeded configured size limit")
                self.feed_content_sha256 = hashlib.sha256(response.content).hexdigest()
                posts = response.json()
        except Exception as exc:
            raise RuntimeError("Ransomwatch pull failed") from exc
        if not isinstance(posts, list):
            raise RuntimeError("Ransomwatch feed schema invalid")
        observed = datetime.now(UTC)
        self.feed_checked = True
        self.feed_observed_at = observed.isoformat()
        self.feed_entries_count = len(posts)
        out: list[Finding] = []
        for post in posts[:self.MAX_FEED_ENTRIES]:
            if not isinstance(post, dict):
                continue
            self.posts_checked += 1
            victim = normalize(str(post.get("post_title") or ""))
            raw_url = str(post.get("post_url") or "")
            group = normalize(str(post.get("group_name") or "unknown"))
            if not victim:
                continue
            temporal_class, published = self._classify_published(post.get("discovered"), observed)
            entry_key = hashlib.sha256("\x1f".join((
                victim.strip().casefold(),
                group.strip().casefold(),
                str(published or ""),
                raw_url.strip(),
            )).encode("utf-8")).hexdigest()
            self.temporal_records.append({
                "record_key": entry_key,
                "temporal_class": temporal_class,
                "published": published,
                "feed_observed_at": self.feed_observed_at,
                "feed_content_sha256": self.feed_content_sha256,
                "victim_name": victim,
                "group": group,
                "source_url": raw_url or None,
            })
            if temporal_class == "current_feed":
                self.current_post_count += 1
            elif temporal_class == "future_dated":
                self.future_dated_post_count += 1
            else:
                self.historical_post_count += 1
            victim_domain = _domain_from_victim_title(victim)
            metadata = {
                "group": group,
                "victim_name": victim,
                "domain": victim_domain,
                "published": published,
                "temporal_class": temporal_class,
                "feed_observed_at": self.feed_observed_at,
                "feed_content_sha256": self.feed_content_sha256,
                "feed_source": "ransomwatch_public_aggregated_feed",
                "direct_onion_access_verified": False,
            }
            # Preserve a durable, tenant-independent source record for temporal
            # history. Hash stable identity fields; never store raw feed payloads.
            record_identity = chr(31).join((
                raw_url.strip(),
                victim.casefold(),
                group.casefold(),
                published or "",
            ))
            record_key = hashlib.sha256(record_identity.encode("utf-8")).hexdigest()
            metadata["record_key"] = record_key
            self.temporal_records.append({
                "record_key": record_key,
                "source_url": raw_url[:2048] or None,
                "victim_name": victim[:512],
                "victim_domain": victim_domain,
                "group_name": group[:256] or "unknown",
                "published_at": published,
                "temporal_class": temporal_class,
                "feed_observed_at": self.feed_observed_at,
                "feed_content_sha256": self.feed_content_sha256,
            })
            if victim_domain:
                out.append(Finding(
                    self.SOURCE, "domain", victim_domain,
                    "Victim domain named in the public Ransomwatch aggregated ransomware-leak feed; not direct onion-site verification.",
                    "critical", raw_url or None, metadata,
                ))
            out.append(Finding(
                self.SOURCE, "company_name", victim,
                "Organization name listed in the public Ransomwatch aggregated ransomware-leak feed; not direct onion-site verification.",
                "critical", raw_url or None, metadata,
            ))
        return out


class TelegramPublicMonitor:
    SOURCE = "telegram_public"

    def __init__(self, channels: list[str]) -> None:
        self.channels = list(dict.fromkeys(c.strip().lstrip("@") for c in channels if c.strip()))
        # Per-channel outcomes remain available to the scheduler for honest coverage.
        self.channel_status: dict[str, str] = {}

    async def pull(self, target_type: str | None = None, target: str | None = None) -> list[Finding]:
        semaphore = asyncio.Semaphore(5)
        target = normalize(target) if target else None
        target_kind = {"email": "email", "domain": "domain", "url": "domain"}.get(target_type or "")

        async def pull_channel(channel: str) -> tuple[str, list[Finding] | None]:
            try:
                async with semaphore:
                    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                        response = await client.get(
                            f"https://t.me/s/{channel}",
                            headers={"user-agent": "cyclothone-darkweb/1.0"},
                        )
                        response.raise_for_status()
                        html = response.text
                if target and target_kind:
                    haystack = html.casefold()
                    matched = target.casefold() in haystack
                    if target_kind == "domain":
                        matched = bool(re.search(r"(?<![a-z0-9.-])" + re.escape(target.casefold()) + r"(?![a-z0-9.-])", haystack))
                    findings = ([Finding(
                        self.SOURCE, target_kind, target,
                        "Requested identifier observed in a public Telegram web preview; page content is not retained.",
                        "high", f"https://t.me/s/{channel}", {"channel": channel, "observed_text_sha256": hashlib.sha256(html.encode()).hexdigest()},
                    )] if matched else [])
                else:
                    findings = [
                        Finding(
                            self.SOURCE, "email", normalize(email),
                            "Email identifier appeared in a public Telegram web preview; page content is not retained.",
                            "medium", f"https://t.me/s/{channel}", {"channel": channel},
                        )
                        for email in dict.fromkeys(EMAIL_RE.findall(html))
                    ]
                return channel, findings
            except Exception as exc:
                logger.warning("Telegram channel failed channel=%s error=%s", channel, type(exc).__name__)
                return channel, None

        results = await asyncio.gather(*(pull_channel(channel) for channel in self.channels))
        self.channel_status = {
            channel: "checked" if findings is not None else "failed"
            for channel, findings in results
        }
        successful = [findings for _, findings in results if findings is not None]
        if self.channels and not successful:
            raise RuntimeError("all configured Telegram public channels failed")
        return [finding for batch in successful for finding in batch]


def _paste_entries_from_feed(text: str) -> list[tuple[str, str, str]]:
    """Extract validated public Pastebin.ca feed entries; never fetch arbitrary URLs."""
    try:
        payload = json.loads(text)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("paste_feed_invalid_json") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        raise ValueError("paste_feed_invalid_schema")
    items = payload["items"]
    entries: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    id_pattern = re.compile(r"^[23456789][23456789A-HJ-NP-Za-hjkmnp-z]{9}$")
    allowed_raw_hosts = {"pastebin.ca", "raw.anybin.ca"}
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        paste_id = str(item.get("id") or "").strip()
        raw_url = str(item.get("raw_url") or "").strip()
        public_url = str(item.get("url") or "").strip()
        raw = urlsplit(raw_url)
        public = urlsplit(public_url)
        if not id_pattern.fullmatch(paste_id) or paste_id in seen:
            continue
        if raw.scheme != "https" or (raw.hostname or "").lower() not in allowed_raw_hosts:
            continue
        if public.scheme != "https" or (public.hostname or "").lower() != "pastebin.ca":
            public_url = raw_url
        seen.add(paste_id)
        entries.append((paste_id, raw_url, public_url))
    return entries[:20]


class PastePublicMonitor:
    SOURCE = "pastebin_public"
    # The previous pastebin.com feed returned 404 in production. This documented
    # public feed is the supported Pastebin.ca JSON API.
    FEED = "https://pastebin.ca/api/v1/feed?limit=20"

    def __init__(self) -> None:
        self.items_checked = 0
        self.feed_checked = False
        self.feed_entries_count = 0

    async def pull(self, target_type: str | None = None, target: str | None = None) -> list[Finding]:
        target = normalize(target) if target else None
        target_kind = {"email": "email", "domain": "domain", "url": "domain"}.get(target_type or "")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(self.FEED, headers={"user-agent": "cyclothone-darkweb/1.0"})
                response.raise_for_status()
                self.feed_checked = True
                entries = _paste_entries_from_feed(response.text)
                self.feed_entries_count = len(entries)
                self.items_checked = 0
                if not entries:
                    return []
                semaphore = asyncio.Semaphore(5)

                async def fetch_paste(entry: tuple[str, str, str]):
                    paste_id, raw_url, public_url = entry
                    async with semaphore:
                        raw = await client.get(
                            raw_url,
                            headers={"user-agent": "cyclothone-darkweb/1.0"},
                        )
                        raw.raise_for_status()
                        return paste_id, public_url, raw.text

                results = await asyncio.gather(
                    *(fetch_paste(entry) for entry in entries),
                    return_exceptions=True,
                )
        except Exception as exc:
            raise RuntimeError("public paste feed pull failed") from exc

        successful = 0
        findings: list[Finding] = []
        for result in results:
            if isinstance(result, BaseException):
                logger.warning("public paste item fetch failed error=%s", type(result).__name__)
                continue
            paste_id, public_url, content = result
            successful += 1
            if target and target_kind:
                haystack = content.casefold()
                matched = target.casefold() in haystack
                if target_kind == "domain":
                    matched = bool(re.search(r"(?<![a-z0-9.-])" + re.escape(target.casefold()) + r"(?![a-z0-9.-])", haystack))
                if matched:
                    findings.append(Finding(
                        self.SOURCE, target_kind, target,
                        "Requested identifier observed in public paste content; paste contents are not retained.",
                        "medium", public_url,
                        {"paste_id": paste_id, "observed_text_sha256": hashlib.sha256(content.encode()).hexdigest()},
                    ))
            else:
                for email in dict.fromkeys(EMAIL_RE.findall(content)):
                    findings.append(Finding(
                        self.SOURCE, "email", normalize(email),
                        "Email identifier appeared in public paste content; paste contents are not retained.",
                        "medium", public_url, {"paste_id": paste_id},
                    ))
        self.items_checked = successful
        if entries and successful == 0:
            raise RuntimeError("all public paste item fetches failed")
        return findings


class BlueskyPublicMonitor:
    """Search public Bluesky posts for an explicitly supplied customer identifier.

    Uses the public AppView endpoint without credentials. A successful API response
    is a source check even when it returns zero matching posts; it does not imply
    exhaustive coverage of deleted, private, unindexed, or rate-limited content.
    """
    SOURCE = "bluesky_public"
    ENDPOINT = "https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts"

    def __init__(self) -> None:
        self.posts_checked = 0

    async def pull(self, target_type: str, target: str) -> list[Finding]:
        target = normalize(target)
        if target_type not in {"domain", "url", "email", "brand", "username", "ip"}:
            raise RuntimeError("unsupported Bluesky target type")
        if not target or len(target) > 253:
            raise RuntimeError("invalid Bluesky search target")
        params = {"q": target, "limit": 25, "sort": "latest"}
        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
                response = await client.get(
                    self.ENDPOINT, params=params,
                    headers={"user-agent": "Cyclothone-DW-Monitor/1.0"},
                )
                response.raise_for_status()
                payload = response.json()
        except Exception as exc:
            raise RuntimeError("Bluesky public search failed") from exc
        posts = payload.get("posts", []) if isinstance(payload, dict) else []
        if not isinstance(posts, list):
            raise RuntimeError("invalid Bluesky public search response")
        self.posts_checked = min(len(posts), 25)
        out: list[Finding] = []
        needle = target.casefold()
        for item in posts[:25]:
            if not isinstance(item, dict):
                continue
            record = item.get("record") or {}
            text = str(record.get("text") or "")
            lowered_text = text.casefold()
            if target_type in {"domain", "url"}:
                matched = bool(re.search(r"(?<![a-z0-9.-])" + re.escape(needle) + r"(?![a-z0-9.-])", lowered_text))
            else:
                matched = needle in lowered_text
            if not matched:
                continue
            author = item.get("author") or {}
            handle = str(author.get("handle") or "")
            uri = str(item.get("uri") or "")
            rkey = uri.rsplit("/", 1)[-1] if uri else ""
            post_url = f"https://bsky.app/profile/{handle}/post/{rkey}" if handle and rkey else None
            kind = {
                "email": "email", "username": "username", "brand": "company_name",
                "ip": "ip", "other": "other", "domain": "domain", "url": "domain",
            }[target_type]
            out.append(Finding(
                self.SOURCE, kind, target,
                "Exact identifier text observed in a public Bluesky post; post text is not retained.",
                "medium", post_url,
                {"author_handle": handle, "post_uri": uri, "observed_text_sha256": hashlib.sha256(text.encode()).hexdigest()},
            ))
        return out


class GitHubCodeMonitor:
    SOURCE = "github_code"
    BASE = "https://api.github.com/search/code"

    def __init__(self, token: str) -> None:
        self.token = token

    async def pull_domain(self, domain: str) -> list[Finding]:
        headers = {"authorization": f"Bearer {self.token}", "accept": "application/vnd.github+json", "user-agent": "cyclothone-darkweb/1.0"}
        out: list[Finding] = []
        failures = 0
        async with httpx.AsyncClient(timeout=20.0) as client:
            for term in ("password", "api_key", "secret"):
                try:
                    response = await client.get(self.BASE, params={"q": f'"{normalize(domain)}" {term}', "per_page": 30}, headers=headers)
                    response.raise_for_status()
                    for item in (response.json() or {}).get("items", []) or []:
                        repo = str((item.get("repository") or {}).get("full_name") or "")
                        out.append(Finding(self.SOURCE, "domain", normalize(domain), "Potential secret-related code exposure; secret value is not retained.", "high", item.get("html_url"), {"repository": repo, "query_term": term}))
                except Exception:
                    failures += 1
                    logger.warning("GitHub code search failed for domain=%s term=%s", domain, term, exc_info=True)
        if failures == 3:
            raise RuntimeError(f"all GitHub code searches failed for {domain}")
        return out
