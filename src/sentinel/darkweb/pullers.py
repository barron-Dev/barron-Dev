from __future__ import annotations

import hashlib
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
                    headers={"hibp-api-key": self.api_key, "user-agent": "sentinel-dw/1.0"},
                )
                if response.status_code == 404:
                    return []
                response.raise_for_status()
                data = response.json()
        except Exception as exc:
            logger.warning("HIBP pull failed: %s", exc)
            return []
        findings: list[Finding] = []
        for alias, breaches in (data or {}).items():
            email = normalize(alias if "@" in alias else f"{alias}@{domain}")
            for breach in breaches or []:
                findings.append(Finding(self.SOURCE, "email", email, "Identifier appeared in a reported breach.", "high", None, {"breach": str(breach), "domain": domain}))
        return findings


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
            logger.warning("Ransomwatch pull failed: %s", exc)
            return []
        out: list[Finding] = []
        for post in posts[:5000] if isinstance(posts, list) else []:
            victim = normalize(str(post.get("post_title") or ""))
            raw_url = str(post.get("post_url") or "")
            group = normalize(str(post.get("group_name") or "unknown"))
            if not victim:
                continue
            host = normalize(urlsplit(raw_url).hostname or raw_url)
            metadata = {"group": group, "victim_name": victim, "published": post.get("discovered")}
            if host:
                out.append(Finding(self.SOURCE, "domain", host, "Organization listed on a ransomware leak feed.", "critical", raw_url or None, metadata))
            out.append(Finding(self.SOURCE, "company_name", victim, "Organization name listed on a ransomware leak feed.", "critical", raw_url or None, {**metadata, "domain": host or None}))
        return out


class TelegramPublicMonitor:
    SOURCE = "telegram_public"

    def __init__(self, channels: list[str]) -> None:
        self.channels = [c.strip().lstrip("@") for c in channels if c.strip()]

    async def pull(self) -> list[Finding]:
        out: list[Finding] = []
        for channel in self.channels:
            try:
                async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                    response = await client.get(f"https://t.me/s/{channel}", headers={"user-agent": "sentinel-dw/1.0"})
                    if response.status_code != 200:
                        continue
                    html = response.text
                for email in dict.fromkeys(EMAIL_RE.findall(html)):
                    out.append(Finding(self.SOURCE, "email", normalize(email), "Monitored identifier appeared in a public Telegram web preview; credential material redacted.", "critical", f"https://t.me/s/{channel}", {"channel": channel}))
            except Exception as exc:
                logger.debug("Telegram channel %s failed: %s", channel, exc)
        return out


class PastePublicMonitor:
    SOURCE = "pastebin_public"
    FEED = "https://pastebin.com/feed/"

    async def pull(self) -> list[Finding]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(self.FEED, headers={"user-agent": "sentinel-dw/1.0"})
                response.raise_for_status()
                text = response.text
        except Exception as exc:
            logger.debug("Paste feed failed: %s", exc)
            return []
        return [Finding(self.SOURCE, "email", normalize(email), "Monitored identifier appeared in a public paste feed.", "medium", self.FEED, {}) for email in dict.fromkeys(EMAIL_RE.findall(text))]


class GitHubCodeMonitor:
    SOURCE = "github_code"
    BASE = "https://api.github.com/search/code"

    def __init__(self, token: str) -> None:
        self.token = token

    async def pull_domain(self, domain: str) -> list[Finding]:
        headers = {"authorization": f"Bearer {self.token}", "accept": "application/vnd.github+json", "user-agent": "sentinel-dw/1.0"}
        out: list[Finding] = []
        async with httpx.AsyncClient(timeout=20.0) as client:
            for term in ("password", "api_key", "secret"):
                try:
                    response = await client.get(self.BASE, params={"q": f'"{normalize(domain)}" {term}', "per_page": 30}, headers=headers)
                    if response.status_code != 200:
                        continue
                    for item in (response.json() or {}).get("items", []) or []:
                        repo = str((item.get("repository") or {}).get("full_name") or "")
                        out.append(Finding(self.SOURCE, "domain", normalize(domain), "Potential secret-related code exposure; secret value is not retained.", "high", item.get("html_url"), {"repository": repo, "query_term": term}))
                except Exception as exc:
                    logger.debug("GitHub code search failed: %s", exc)
        return out
