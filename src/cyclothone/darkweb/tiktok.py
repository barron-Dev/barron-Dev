from __future__ import annotations

import logging
import os
import re
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import httpx

from cyclothone.darkweb.pullers import Finding, normalize

logger = logging.getLogger(__name__)


class TikTokCommercialContentMonitor:
    """Query TikTok's approved Commercial Content API for public EU ad-library data.

    This source is intentionally limited to commercial/ad data. It does not claim
    to search all organic TikTok videos or monitor arbitrary creators' timelines.
    """

    SOURCE = "tiktok_commercial"
    TOKEN_ENDPOINT = "https://open.tiktokapis.com/v2/oauth/token/"
    QUERY_ENDPOINT = "https://open.tiktokapis.com/v2/research/adlib/ad/query/"
    FIELDS = "ad.id,ad.first_shown_date,ad.last_shown_date,ad.advertiser_name,ad.videos"
    EU_COUNTRIES = [
        "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
        "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
        "PL", "PT", "RO", "SK", "SI", "ES", "SE",
    ]
    MAX_PAGES = 3

    def __init__(self, client_key: str | None = None, client_secret: str | None = None) -> None:
        self.client_key = (client_key if client_key is not None else os.getenv("CYCLOTHONE_TIKTOK_CLIENT_KEY", "")).strip()
        self.client_secret = (client_secret if client_secret is not None else os.getenv("CYCLOTHONE_TIKTOK_CLIENT_SECRET", "")).strip()
        self.coverage_partial = False

    @staticmethod
    def _matches_target(kind: str, target: str, text: str, advertiser: str) -> bool:
        haystack = " ".join((text or "", advertiser or "")).strip()
        if not haystack:
            return False
        target = target.strip().lower()
        if kind == "domain":
            return bool(re.search(r"(?<![a-z0-9.-])" + re.escape(target) + r"(?![a-z0-9.-])", haystack, re.IGNORECASE))
        if kind == "company_name":
            return bool(re.search(r"(?<!\w)" + re.escape(target) + r"(?!\w)", haystack, re.IGNORECASE))
        if kind == "username":
            handle = target.lstrip("@")
            if normalize(advertiser).lstrip("@") == handle:
                return True
            return bool(re.search(r"(?<![a-z0-9_])@" + re.escape(handle) + r"(?![a-z0-9_])", haystack, re.IGNORECASE))
        return False

    @staticmethod
    def _safe_tiktok_url(value: object) -> str | None:
        raw = str(value or "").strip()
        if not raw:
            return None
        parsed = urlsplit(raw)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or not host or not (host == "tiktok.com" or host.endswith(".tiktok.com")):
            return None
        return raw

    async def _client_token(self, client: httpx.AsyncClient) -> str:
        response = await client.post(
            self.TOKEN_ENDPOINT,
            data={
                "client_key": self.client_key,
                "client_secret": self.client_secret,
                "grant_type": "client_credentials",
            },
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        response.raise_for_status()
        payload = response.json()
        token = str(payload.get("access_token") or "").strip()
        if not token:
            raise RuntimeError("tiktok_client_access_token_missing")
        return token

    async def pull_target(self, kind: str, target: str) -> list[Finding]:
        return await self.pull_targets([(kind, target)])

    async def pull_targets(self, targets: list[tuple[str, str]]) -> list[Finding]:
        if not self.client_key or not self.client_secret:
            raise RuntimeError("tiktok_commercial_credentials_required")
        supported = {"domain", "company_name", "username"}
        targets = [
            (str(kind).strip().lower(), str(value).strip().lower())
            for kind, value in targets
            if str(kind).strip().lower() in supported and str(value).strip()
        ][:20]
        if not targets:
            return []
        self.coverage_partial = False
        today = datetime.now(UTC).date()
        date_max = today.strftime("%Y%m%d")
        date_min = (today - timedelta(days=30)).strftime("%Y%m%d")
        findings: list[Finding] = []
        async with httpx.AsyncClient(timeout=25.0, follow_redirects=False) as client:
            token = await self._client_token(client)
            for kind, target in targets:
                search_term = target.lstrip("@") if kind == "username" else target
                search_id: str | None = None
                for page in range(self.MAX_PAGES):
                    body = {
                        "filters": {
                            "ad_published_date_range": {"min": date_min, "max": date_max},
                            "country_code_list": self.EU_COUNTRIES,
                        },
                        "search_term": search_term,
                        "max_count": 20,
                    }
                    if search_id:
                        body["search_id"] = search_id
                    response = await client.post(
                        self.QUERY_ENDPOINT,
                        params={"fields": self.FIELDS},
                        json=body,
                        headers={
                            "authorization": f"Bearer {token}",
                            "content-type": "application/json",
                            "user-agent": "CyclothonePublicExposureMonitor/1.0",
                        },
                    )
                    response.raise_for_status()
                    payload = response.json()
                    error = payload.get("error") or {}
                    error_code = str(error.get("code") or "ok").lower()
                    if error_code not in {"ok", "0"}:
                        raise RuntimeError("tiktok_commercial_api_error")
                    data = payload.get("data") or {}
                    ads = data.get("ads")
                    if not isinstance(ads, list):
                        raise RuntimeError("tiktok_commercial_response_schema_invalid")
                    for item in ads:
                        if not isinstance(item, dict):
                            continue
                        ad = item.get("ad") if isinstance(item.get("ad"), dict) else item
                        ad_id = str(ad.get("id") or ad.get("ad_id") or item.get("id") or "").strip()
                        advertiser = str(ad.get("advertiser_name") or item.get("advertiser_name") or "")
                        videos = ad.get("videos") or item.get("videos") or []
                        if isinstance(videos, dict):
                            videos = [videos]
                        if not isinstance(videos, list) or not videos:
                            videos = [{}]
                        for video in videos:
                            if not isinstance(video, dict):
                                continue
                            searchable = " ".join(str(video.get(field) or "") for field in (
                                "title", "description", "video_title", "video_description", "caption"
                            ))
                            if not self._matches_target(kind, target, searchable, advertiser):
                                continue
                            video_id = str(video.get("video_id") or video.get("id") or "").strip()
                            source_url = (
                                self._safe_tiktok_url(video.get("video_url"))
                                or self._safe_tiktok_url(video.get("url"))
                                or "https://library.tiktok.com/ads"
                            )
                            findings.append(Finding(
                                self.SOURCE,
                                kind,
                                target,
                                "Exact target match in TikTok public commercial-content metadata; this is ad-library coverage, not a search of all organic videos.",
                                "medium",
                                source_url,
                                {
                                    "platform": "tiktok",
                                    "dataset": "commercial_content_ads",
                                    "ad_id": ad_id or None,
                                    "video_id": video_id or None,
                                    "advertiser_name": advertiser or None,
                                    "first_shown_date": ad.get("first_shown_date") or item.get("first_shown_date"),
                                    "last_shown_date": ad.get("last_shown_date") or item.get("last_shown_date"),
                                    "target_kind": kind,
                                },
                            ))
                    has_more = bool(data.get("has_more"))
                    next_search_id = str(data.get("search_id") or "").strip()
                    if not has_more:
                        break
                    if not next_search_id or page == self.MAX_PAGES - 1:
                        self.coverage_partial = True
                        break
                    search_id = next_search_id
        # Deduplicate identical ad/video evidence returned across pages.
        unique: dict[tuple[str, str, str], Finding] = {}
        for finding in findings:
            metadata = finding.metadata or {}
            key = (
                str(metadata.get("ad_id") or ""),
                str(metadata.get("video_id") or ""),
                str(finding.matched_value),
            )
            unique[key] = finding
        return list(unique.values())
