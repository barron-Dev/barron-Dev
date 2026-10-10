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
        successful = [findings for _, findings in results if findings is not None]
        if self.channels and not successful:
            raise RuntimeError("all configured Telegram public channels failed")
        return [finding for batch in successful for finding in batch]


def _paste_entries_from_feed(text: str) -> list[tuple[str, str, str]]:
    """Extract validated public Pastebin.ca feed entries; never fetch arbitrary URLs."""
    try:
        payload = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return []
    items = payload.get("items", []) if isinstance(payload, dict) else []
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
