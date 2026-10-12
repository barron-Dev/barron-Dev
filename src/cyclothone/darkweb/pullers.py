from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
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


def normalize(value: str) -> str:
    return value.strip().lower()


def value_hash(value: str) -> str:
    return hashlib.sha256(normalize(value).encode()).hexdigest()


def _redact(text: str) -> str:
    # Never retain password material from credential-pair matches.
    return EMAIL_RE.sub("[email]", text)[:2000]


class HIBPPuller:
    SOURCE = "hibp"
    BASE = "https://haveibeenpwned.com/api/v3"

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    async def pull_domain(self, domain: str) -> list[Finding]:
        domain = normalize(domain)
        if not domain or len(domain) > 253:
            return []
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.get(
                    f"{self.BASE}/breacheddomain/{domain}",
                    headers={"hibp-api-key": self.api_key, "user-agent": "cyclothone-darkweb/1.0"},
                )
                if response.status_code == 404:
                    return []
                response.raise_for_status()
                data = response.json()
        except Exception as exc:
            raise RuntimeError(f"HIBP pull failed for {domain}") from exc
        findings: list[Finding] = []
        for alias, breaches in (data or {}).items():
            email = normalize(alias if "@" in alias else f"{alias}@{domain}")
            for breach in breaches or []:
                findings.append(Finding(self.SOURCE, "email", email, "Identifier appeared in a reported breach.", "high", None, {"breach": str(breach), "domain": domain}))
        return findings

    async def pull_account(self, email: str) -> list[Finding]:
        """Check one explicitly supplied email address using HIBP's account endpoint."""
        email = normalize(email)
        if "@" not in email or email.count("@") != 1 or len(email) > 320:
            return []
        from urllib.parse import quote

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.get(
                    f"{self.BASE}/breachedaccount/{quote(email, safe='')}",
                    params={"truncateResponse": "false", "includeUnverified": "false"},
                    headers={"hibp-api-key": self.api_key, "user-agent": "cyclothone-darkweb/1.0"},
                )
                if response.status_code == 404:
                    return []
                response.raise_for_status()
                breaches = response.json()
        except Exception as exc:
            raise RuntimeError("HIBP account pull failed") from exc
        return [
            Finding(
                self.SOURCE, "email", email,
                "Email identifier appeared in a reported breach.",
                "high", None,
                {"breach": str(breach.get("Name") or breach.get("Title") or "reported breach")},
            )
            for breach in (breaches or [])
            if isinstance(breach, dict)
        ]


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
    SOURCE = "ransomwatch"
    FEED = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"

    async def pull(self) -> list[Finding]:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(self.FEED)
                response.raise_for_status()
                posts = response.json()
        except Exception as exc:
            raise RuntimeError("Ransomwatch pull failed") from exc
        out: list[Finding] = []
        for post in posts[:5000] if isinstance(posts, list) else []:
            victim = normalize(str(post.get("post_title") or ""))
            raw_url = str(post.get("post_url") or "")
            group = normalize(str(post.get("group_name") or "unknown"))
            if not victim:
                continue
            victim_domain = _domain_from_victim_title(victim)
            metadata = {
                "group": group,
                "victim_name": victim,
                "domain": victim_domain,
                "published": post.get("discovered"),
            }
            if victim_domain:
                out.append(Finding(
                    self.SOURCE, "domain", victim_domain,
                    "Victim domain explicitly named in a ransomware leak feed.",
                    "critical", raw_url or None, metadata,
                ))
            out.append(Finding(
                self.SOURCE, "company_name", victim,
                "Organization name listed on a ransomware leak feed.",
                "critical", raw_url or None, metadata,
            ))
        return out


class TelegramPublicMonitor:
    SOURCE = "telegram_public"

    def __init__(self, channels: list[str]) -> None:
        self.channels = list(dict.fromkeys(c.strip().lstrip("@") for c in channels if c.strip()))
        # Per-channel outcomes remain available to the scheduler for honest coverage.
        self.channel_status: dict[str, str] = {}

    async def pull(self) -> list[Finding]:
        semaphore = asyncio.Semaphore(5)

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
                findings = [
                    Finding(
                        self.SOURCE, "email", normalize(email),
                        "Monitored identifier appeared in a public Telegram web preview; credential material redacted.",
                        "critical", f"https://t.me/s/{channel}", {"channel": channel},
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

    async def pull(self) -> list[Finding]:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(self.FEED, headers={"user-agent": "cyclothone-darkweb/1.0"})
                response.raise_for_status()
                entries = _paste_entries_from_feed(response.text)
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
            for email in dict.fromkeys(EMAIL_RE.findall(content)):
                findings.append(Finding(
                    self.SOURCE,
                    "email",
                    normalize(email),
                    "Identifier appeared in public paste content; paste contents are not retained.",
                    "medium",
                    public_url,
                    {"paste_id": paste_id},
                ))
        if entries and successful == 0:
            raise RuntimeError("all public paste item fetches failed")
        return findings



class MetaPublicMonitor:
    """Search permitted public Meta content through official Graph API endpoints.

    Instagram searches recent public hashtag media associated with a connected
    professional account. Facebook reads posts only from explicitly configured
    Page IDs that the Meta app is permitted to access. This is not global search
    across every Facebook or Instagram post.
    """
    GRAPH_BASE = "https://graph.facebook.com/v26.0"

    def __init__(
        self,
        access_token: str | None = None,
        instagram_user_id: str | None = None,
        facebook_page_ids: list[str] | None = None,
    ) -> None:
        self.access_token = (access_token if access_token is not None else os.getenv("CYCLOTHONE_META_ACCESS_TOKEN", "")).strip()
        self.instagram_user_id = (instagram_user_id if instagram_user_id is not None else os.getenv("CYCLOTHONE_META_IG_USER_ID", "")).strip()
        raw_pages = os.getenv("CYCLOTHONE_META_FACEBOOK_PAGE_IDS", "") if facebook_page_ids is None else ",".join(facebook_page_ids)
        self.facebook_page_ids = [v.strip() for v in raw_pages.split(",") if v.strip()]

    @staticmethod
    def _search_term(target: str) -> str:
        candidate = normalize(target)
        if "://" in candidate:
            candidate = urlsplit(candidate).hostname or candidate
        candidate = candidate.split("/")[0].split(":")[0]
        if "@" in candidate:
            candidate = candidate.rsplit("@", 1)[-1]
        labels = [part for part in candidate.split(".") if part and part not in {"www", "com", "net", "org", "site", "online", "io", "co", "uk"}]
        return labels[0][:50] if labels else candidate[:50]

    async def pull_instagram_domains(self, domains: list[str]) -> list[Finding]:
        if not self.access_token or not self.instagram_user_id:
            raise RuntimeError("meta_instagram_credentials_required")
        if not domains:
            return []
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=False) as client:
            async def search(domain: str) -> list[Finding]:
                term = self._search_term(domain)
                hashtag = re.sub(r"[^a-zA-Z0-9_]", "", term).lower()
                if len(hashtag) < 2:
                    return []
                common = {"access_token": self.access_token}
                response = await client.get(
                    f"{self.GRAPH_BASE}/{self.instagram_user_id}/ig_hashtag_search",
                    params={**common, "user_id": self.instagram_user_id, "q": hashtag},
                )
                response.raise_for_status()
                hashtag_rows = (response.json() or {}).get("data", [])
                if not hashtag_rows:
                    return []
                hashtag_id = str(hashtag_rows[0].get("id") or "")
                if not hashtag_id:
                    return []
                media_response = await client.get(
                    f"{self.GRAPH_BASE}/{hashtag_id}/recent_media",
                    params={
                        **common,
                        "user_id": self.instagram_user_id,
                        "fields": "id,caption,permalink,timestamp",
                        "limit": 50,
                    },
                )
                media_response.raise_for_status()
                domain_re = re.compile(r"(?i)(?<![a-z0-9.-])" + re.escape(normalize(domain)) + r"(?![a-z0-9.-])")
                findings: list[Finding] = []
                for item in (media_response.json() or {}).get("data", []):
                    caption = str(item.get("caption") or "")
                    if not domain_re.search(caption):
                        continue
                    permalink = str(item.get("permalink") or "")
                    if not permalink.startswith("https://www.instagram.com/"):
                        continue
                    findings.append(Finding(
                        "instagram_public", "domain", normalize(domain),
                        "Monitored domain mentioned in public Instagram hashtag media; caption text is not retained.",
                        "medium", permalink,
                        {"platform": "instagram", "published": item.get("timestamp"), "media_id": str(item.get("id") or "")},
                    ))
                return findings
            batches = await asyncio.gather(*(search(d) for d in domains[:10]), return_exceptions=True)
        failures = sum(isinstance(batch, BaseException) for batch in batches)
        if failures:
            # Fail closed: do not label an incomplete set of domain searches as
            # a complete check. The request worker records this source as failed.
            raise RuntimeError(f"instagram_public_searches_incomplete:{failures}/{len(batches)}")
        return [item for batch in batches if isinstance(batch, list) for item in batch]

    async def pull_facebook_domains(self, domains: list[str]) -> list[Finding]:
        if not self.access_token:
            raise RuntimeError("meta_facebook_access_token_required")
        if not self.facebook_page_ids:
            raise RuntimeError("meta_facebook_page_ids_required")
        if not domains:
            return []
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=False) as client:
            async def page_search(page_id: str, domain: str) -> list[Finding]:
                response = await client.get(
                    f"{self.GRAPH_BASE}/{page_id}/posts",
                    params={
                        "access_token": self.access_token,
                        "fields": "message,permalink_url,created_time,id",
                        "limit": 100,
                    },
                )
                response.raise_for_status()
                domain_re = re.compile(r"(?i)(?<![a-z0-9.-])" + re.escape(normalize(domain)) + r"(?![a-z0-9.-])")
                findings: list[Finding] = []
                for item in (response.json() or {}).get("data", []):
                    if not domain_re.search(str(item.get("message") or "")):
                        continue
                    permalink = str(item.get("permalink_url") or "")
                    if not permalink.startswith("https://www.facebook.com/"):
                        continue
                    findings.append(Finding(
                        "facebook_public", "domain", normalize(domain),
                        "Monitored domain mentioned in a public Facebook Page post; post text is not retained.",
                        "medium", permalink,
                        {"platform": "facebook", "published": item.get("created_time"), "page_id": page_id, "post_id": str(item.get("id") or "")},
                    ))
                return findings
            jobs = [page_search(page_id, domain) for page_id in self.facebook_page_ids[:50] for domain in domains[:10]]
            batches = await asyncio.gather(*jobs, return_exceptions=True)
        failures = sum(isinstance(batch, BaseException) for batch in batches)
        if failures:
            # Do not report a complete source check when any configured Page
            # or target query failed; this prevents silent partial coverage.
            raise RuntimeError(f"facebook_public_page_searches_incomplete:{failures}/{len(batches)}")
        return [item for batch in batches if isinstance(batch, list) for item in batch]


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
