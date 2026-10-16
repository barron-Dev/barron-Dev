from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger(__name__)
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
USER_AGENT = "cyclothone-dw/1.0"


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
    return EMAIL_RE.sub("[email]", text)[:2000]


def as_domain(value: str) -> str | None:
    """Accept a bare domain or URL hostname; reject credentials, paths, IPs, and malformed labels."""
    raw = str(value or "").strip()
    if not raw or len(raw) > 2048 or "@" in raw or any(ch.isspace() for ch in raw):
        return None
    candidate = raw
    if "://" in candidate:
        try:
            parsed = urlsplit(candidate)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
                return None
            candidate = parsed.hostname
        except ValueError:
            return None
    else:
        candidate = candidate.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if ":" in candidate:
            return None
    candidate = candidate.rstrip(".").lower()
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not candidate or len(candidate) > 253 or "." not in candidate:
        return None
    labels = candidate.split(".")
    if any(not DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        return None
    if labels[-1].isdigit() or all(label.isdigit() for label in labels):
        return None
    return candidate


class HIBPPuller:
    SOURCE = "hibp"
    BASE = "https://haveibeenpwned.com/api/v3"

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key.strip()

    async def pull_domain(self, domain: str) -> list[Finding]:
        domain = as_domain(domain) or ""
        if not domain or not self.api_key:
            raise ValueError("valid domain and HIBP API key are required")
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.get(
                    f"{self.BASE}/breacheddomain/{domain}",
                    headers={"hibp-api-key": self.api_key, "user-agent": USER_AGENT},
                )
                if response.status_code == 404:
                    return []
                response.raise_for_status()
                data = response.json()
        except Exception as exc:
            raise RuntimeError(f"HIBP pull failed for {domain}") from exc
        if not isinstance(data, dict):
            raise RuntimeError("HIBP returned an invalid response shape")
        findings: list[Finding] = []
        for alias, breaches in data.items():
            if not isinstance(alias, str) or not isinstance(breaches, list):
                continue
            email = normalize(alias if "@" in alias else f"{alias}@{domain}")
            for breach in breaches:
                if isinstance(breach, str) and breach.strip():
                    findings.append(Finding(self.SOURCE, "email", email, "Identifier appeared in a reported breach.", "high", None, {"breach": breach[:200], "domain": domain}))
        return findings


class RansomwatchPuller:
    SOURCE = "ransomwatch"
    FEED = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"

    async def pull(self) -> list[Finding]:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(self.FEED, headers={"user-agent": USER_AGENT})
                response.raise_for_status()
                posts = response.json()
        except Exception as exc:
            raise RuntimeError("Ransomwatch pull failed") from exc
        if not isinstance(posts, list):
            raise RuntimeError("Ransomwatch returned an invalid response shape")
        out: list[Finding] = []
        for post in posts[:5000]:
            if not isinstance(post, dict):
                continue
            victim = normalize(str(post.get("post_title") or ""))
            raw_url = str(post.get("post_url") or "")
            group = normalize(str(post.get("group_name") or "unknown"))
            if not victim:
                continue
            host = as_domain(raw_url)
            metadata = {"group": group[:200], "victim_name": victim[:512], "published": post.get("discovered"), "match_basis": "public_ransomware_leak_listing", "provenance": "aggregator_listing"}
            if host:
                out.append(Finding(self.SOURCE, "domain", host, "Domain extracted from a public ransomware leak listing; independently unverified.", "high", raw_url or None, metadata))
            out.append(Finding(self.SOURCE, "company_name", victim[:512], "Organization name listed on a public ransomware leak feed; independently unverified.", "high", raw_url or None, {**metadata, "domain": host}))
        return out


class RansomwareLivePuller:
    SOURCE = "ransomware_live"
    ENDPOINT = "https://api.ransomware.live/v2/recentvictims"

    async def pull(self) -> list[Finding]:
        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                response = await client.get(self.ENDPOINT, headers={"user-agent": USER_AGENT, "accept": "application/json"})
                response.raise_for_status()
                payload = response.json()
        except Exception as exc:
            raise RuntimeError("Ransomware.live pull failed") from exc
        if isinstance(payload, dict):
            payload = payload.get("victims", payload.get("data"))
        if not isinstance(payload, list):
            raise RuntimeError("Ransomware.live returned an invalid response shape")
        out: list[Finding] = []
        for item in payload[:5000]:
            if not isinstance(item, dict):
                continue
            victim = str(item.get("victim") or item.get("post_title") or item.get("name") or "").strip()
            group = str(item.get("group_name") or item.get("group") or "unknown").strip()[:200]
            raw_domain = str(item.get("domain") or item.get("website") or "").strip()
            domain = as_domain(raw_domain) if raw_domain else None
            raw_url = str(item.get("url") or item.get("post_url") or "").strip()
            source_url = raw_url if raw_url.startswith(("https://", "http://")) else None
            published = item.get("published") or item.get("discovered") or item.get("date")
            metadata = {"group": group, "victim_name": victim[:512], "published": published, "match_basis": "public_ransomware_leak_listing", "provenance": "aggregator_listing"}
            if domain:
                out.append(Finding(self.SOURCE, "domain", domain, "Domain associated with a public ransomware leak listing; independently unverified.", "high", source_url, metadata))
            if victim:
                out.append(Finding(self.SOURCE, "company_name", victim[:512], "Organization listed by a public ransomware leak aggregator; independently unverified.", "high", source_url, {**metadata, "domain": domain}))
        return out


class RansomLookPuller:
    SOURCE = "ransomlook"
    ENDPOINT = "https://www.ransomlook.io/api/recent/100"

    async def pull(self) -> list[Finding]:
        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                response = await client.get(self.ENDPOINT, headers={"user-agent": USER_AGENT, "accept": "application/json"})
                response.raise_for_status()
                payload = response.json()
        except Exception as exc:
            raise RuntimeError("RansomLook pull failed") from exc
        if isinstance(payload, dict):
            payload = payload.get("recent", payload.get("data", payload.get("posts")))
        if not isinstance(payload, list):
            raise RuntimeError("RansomLook returned an invalid response shape")
        out: list[Finding] = []
        for item in payload[:1000]:
            if not isinstance(item, dict):
                continue
            victim = str(item.get("victim") or item.get("post_title") or item.get("name") or item.get("title") or "").strip()
            if not victim:
                continue
            group = str(item.get("group_name") or item.get("group") or "unknown").strip()[:200]
            raw_domain = str(item.get("domain") or item.get("website") or "").strip()
            domain = as_domain(raw_domain) if raw_domain else None
            raw_url = str(item.get("url") or item.get("post_url") or item.get("link") or "").strip()
            source_url = raw_url if raw_url.startswith(("https://", "http://")) else None
            metadata = {"group": group, "victim_name": victim[:512], "published": item.get("published") or item.get("date"), "domain": domain, "match_basis": "public_ransomware_leak_listing", "provenance": "aggregator_listing"}
            if domain:
                out.append(Finding(self.SOURCE, "domain", domain, "Domain associated with a public ransomware leak listing; independently unverified.", "high", source_url, metadata))
            out.append(Finding(self.SOURCE, "company_name", victim[:512], "Organization listed by a public ransomware leak aggregator; independently unverified.", "high", source_url, metadata))
        return out


class TelegramPublicMonitor:
    SOURCE = "telegram_public"

    def __init__(self, channels: list[str]) -> None:
        self.channels = [c.strip().lstrip("@") for c in channels if c.strip()]

    async def pull(self) -> list[Finding]:
        out: list[Finding] = []
        failures = 0
        for channel in self.channels:
            try:
                async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                    response = await client.get(f"https://t.me/s/{channel}", headers={"user-agent": USER_AGENT})
                    response.raise_for_status()
                    html = response.text
                for email in dict.fromkeys(EMAIL_RE.findall(html)):
                    out.append(Finding(self.SOURCE, "email", normalize(email), "Identifier appeared in a public Telegram web preview; preview is not a complete channel crawl.", "high", f"https://t.me/s/{channel}", {"channel": channel, "coverage": "public_preview", "provenance": "public_web_preview"}))
            except Exception:
                failures += 1
                logger.warning("Telegram public preview failed for channel=%s", channel, exc_info=True)
        if self.channels and failures == len(self.channels):
            raise RuntimeError("all configured Telegram public channels failed")
        return out


class PastePublicMonitor:
    SOURCE = "pastebin_public"
    FEED = "https://pastebin.com/feed/"

    async def pull(self) -> list[Finding]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(self.FEED, headers={"user-agent": USER_AGENT})
                response.raise_for_status()
                text = response.text
        except Exception as exc:
            raise RuntimeError("public paste feed pull failed") from exc
        return [Finding(self.SOURCE, "email", normalize(email), "Identifier appeared in a public paste feed; feed coverage is limited to this endpoint.", "medium", self.FEED, {"coverage": "public_feed", "provenance": "public_feed"}) for email in dict.fromkeys(EMAIL_RE.findall(text))]


class GitHubCodeMonitor:
    SOURCE = "github_code"
    BASE = "https://api.github.com/search/code"

    def __init__(self, token: str) -> None:
        self.token = token.strip()

    async def pull_domain(self, domain: str) -> list[Finding]:
        domain = as_domain(domain) or ""
        if not domain or not self.token:
            raise ValueError("valid domain and GitHub token are required")
        headers = {"authorization": f"Bearer {self.token}", "accept": "application/vnd.github+json", "user-agent": USER_AGENT}
        out: list[Finding] = []
        failures = 0
        async with httpx.AsyncClient(timeout=20.0) as client:
            for term in ("password", "api_key", "secret"):
                try:
                    response = await client.get(self.BASE, params={"q": f'"{domain}" {term}', "per_page": 30}, headers=headers)
                    response.raise_for_status()
                    payload = response.json()
                    if not isinstance(payload, dict) or not isinstance(payload.get("items", []), list):
                        raise RuntimeError("GitHub code search returned an invalid response shape")
                    for item in payload.get("items", []) or []:
                        if not isinstance(item, dict):
                            continue
                        repo = str((item.get("repository") or {}).get("full_name") or "")
                        out.append(Finding(self.SOURCE, "domain", domain, "Potential secret-related code exposure; secret values are not retained.", "high", item.get("html_url"), {"repository": repo, "query_term": term, "match_basis": "code_search_candidate"}))
                except Exception:
                    failures += 1
                    logger.warning("GitHub code search failed for domain=%s term=%s", domain, term, exc_info=True)
        if failures == 3:
            raise RuntimeError(f"all GitHub code searches failed for {domain}")
        return out
