from __future__ import annotations

import hashlib
import logging

import httpx

from cyclothone.brand.similarity import combined_similarity
from cyclothone.storage.supabase_client import supabase

logger = logging.getLogger(__name__)


class SocialMonitor:
    PLATFORMS = {
        "x": "https://x.com/{h}",
        "instagram": "https://www.instagram.com/{h}/",
        "facebook": "https://www.facebook.com/{h}",
        "tiktok": "https://www.tiktok.com/@{h}",
        "youtube": "https://www.youtube.com/@{h}",
        "linkedin": "https://www.linkedin.com/company/{h}",
        "telegram": "https://t.me/{h}",
    }

    async def scan_brand(self, brand):
        base = brand["primary_domain"].split(".")[0].lower()
        owned = {item.lower() for item in brand.get("social_handles", [])}
        stats = {
            "checked": 0,
            "candidate_matches": 0,
            "recorded_candidates": 0,
            "persistence_failures": 0,
            "source_errors": 0,
            "verified_threats": 0,
        }
        variants = list(dict.fromkeys([
            base, base + "hq", base + "official", base + "_official",
            "official" + base, base + "support", base + "help",
            base + "team", "real" + base, base + "_app",
        ]))
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            for platform, template in self.PLATFORMS.items():
                for handle in variants:
                    if handle in owned:
                        continue
                    stats["checked"] += 1
                    url = template.format(h=handle)
                    try:
                        response = await client.get(
                            url, headers={"user-agent": "CyclothoneBrand/1.0"}
                        )
                    except Exception:
                        stats["source_errors"] += 1
                        continue
                    # HTTP 200 proves only that a page responded, not that it
                    # impersonates the tenant's brand.
                    if response.status_code != 200:
                        continue
                    similarity = combined_similarity(handle, base)
                    severity = (
                        "critical" if similarity >= 0.9
                        else "high" if similarity >= 0.8
                        else "medium"
                    )
                    stats["candidate_matches"] += 1
                    persisted = await self._record(
                        brand["tenant_id"], brand["id"],
                        platform + ":" + handle, str(response.url), platform,
                        similarity, severity,
                        {
                            "handle": handle,
                            "source": "public_social_profile_probe",
                            "http_status": response.status_code,
                            "verification_state": "candidate",
                            "evidence_stage": "profile_http_response_only",
                            "evidence_sha256": hashlib.sha256(response.content).hexdigest(),
                            "profile_identity_verified": False,
                            "brand_authorization_verified": False,
                        },
                    )
                    if persisted:
                        stats["recorded_candidates"] += 1
                    else:
                        stats["persistence_failures"] += 1
        return stats

    async def _record(self, tenant, brand, identifier, url, platform, similarity, severity, metadata):
        async def query():
            return await (
                await supabase._ensure()
            ).rpc(
                "record_brand_threat",
                {
                    "p_tenant": tenant,
                    "p_brand": brand,
                    "p_kind": "social_handle",
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
            logger.warning("social candidate persistence failed", exc_info=True)
            return False
