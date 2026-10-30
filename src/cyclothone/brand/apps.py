from __future__ import annotations

import hashlib
import json
import logging
import re

import httpx

from cyclothone.brand.similarity import combined_similarity
from cyclothone.storage.supabase_client import supabase

logger = logging.getLogger(__name__)


class AppStoreMonitor:
    ITUNES = "https://itunes.apple.com/search"

    async def scan_brand(self, brand):
        base = brand["primary_domain"].split(".")[0].lower()
        stats = {
            "checked": 0,
            "candidate_matches": 0,
            "recorded_candidates": 0,
            "persistence_failures": 0,
            "source_errors": 0,
            "verified_threats": 0,
        }
        async with httpx.AsyncClient(timeout=20) as client:
            try:
                response = await client.get(
                    self.ITUNES,
                    params={"term": base, "entity": "software", "limit": 100},
                )
                items = (
                    (response.json() or {}).get("results", [])
                    if response.status_code == 200 else []
                )
                if response.status_code != 200:
                    stats["source_errors"] += 1
            except Exception:
                items = []
                stats["source_errors"] += 1

            app_ids = brand.get("app_ids") or {}
            own_ios = {
                str(value) for value in app_ids.get("ios", [])
            } if isinstance(app_ids.get("ios"), list) else set()

            for app in items:
                stats["checked"] += 1
                track_id = str(app.get("trackId") or "")
                if track_id in own_ios:
                    continue
                name = str(app.get("trackName") or "")
                seller = str(app.get("sellerName") or "")
                similarity = max(
                    combined_similarity(name, base),
                    combined_similarity(seller, base),
                )
                if similarity < 0.6:
                    continue
                stats["candidate_matches"] += 1
                source_record = json.dumps(
                    app, sort_keys=True, separators=(",", ":")
                ).encode()
                persisted = await self._record(
                    brand, "ios:" + str(app.get("bundleId") or track_id),
                    app.get("trackViewUrl"), "ios", similarity,
                    "critical" if similarity >= 0.85 else "high",
                    {
                        "name": name,
                        "seller": seller,
                        "source": "apple_itunes_search",
                        "verification_state": "candidate",
                        "evidence_stage": "store_listing_similarity_only",
                        "evidence_sha256": hashlib.sha256(source_record).hexdigest(),
                        "seller_authority_verified": False,
                        "brand_authorization_verified": False,
                    },
                )
                if persisted:
                    stats["recorded_candidates"] += 1
                else:
                    stats["persistence_failures"] += 1

            try:
                response = await client.get(
                    "https://play.google.com/store/search",
                    params={"q": base, "c": "apps"},
                    headers={"user-agent": "CyclothoneBrand/1.0"},
                )
                html = response.text if response.status_code == 200 else ""
                if response.status_code != 200:
                    stats["source_errors"] += 1
            except Exception:
                html = ""
                stats["source_errors"] += 1

            for package in list(set(re.findall(r"id=(com\.[A-Za-z0-9_.]{3,120})", html)))[:100]:
                stats["checked"] += 1
                similarity = combined_similarity(package.split(".")[-1], base)
                if similarity < 0.6:
                    continue
                stats["candidate_matches"] += 1
                digest = hashlib.sha256(package.encode()).hexdigest()
                persisted = await self._record(
                    brand, "android:" + package,
                    "https://play.google.com/store/apps/details?id=" + package,
                    "android", similarity,
                    "critical" if similarity >= 0.85 else "high",
                    {
                        "package": package,
                        "source": "google_play_search",
                        "verification_state": "candidate",
                        "evidence_stage": "store_package_similarity_only",
                        "evidence_sha256": digest,
                        "brand_authorization_verified": False,
                    },
                )
                if persisted:
                    stats["recorded_candidates"] += 1
                else:
                    stats["persistence_failures"] += 1
        return stats

    async def _record(self, brand, identifier, url, platform, similarity, severity, metadata):
        async def query():
            return await (
                await supabase._ensure()
            ).rpc(
                "record_brand_threat",
                {
                    "p_tenant": brand["tenant_id"],
                    "p_brand": brand["id"],
                    "p_kind": "fake_app",
                    "p_identifier": identifier,
                    "p_url": url,
                    "p_platform": platform,
                    "p_similarity": similarity,
                    "p_severity": severity,
                    "p_metadata": metadata,
                },
            ).execute()

        try:
            await supabase._retry(query, attempts=2)
            return True
        except Exception:
            logger.warning("app-store candidate persistence failed", exc_info=True)
            return False
