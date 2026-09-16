from __future__ import annotations

import hashlib
import logging
import os
from typing import Any
from uuid import UUID

from sentinel.darkweb.matcher import DarkWebMatcher
from sentinel.storage.supabase_client import supabase
from sentinel.web.crawler import WebCrawler, WebPage

logger = logging.getLogger(__name__)


class WebIntelligenceOrchestrator:
    """Unifies surface, deep and dark collection with the existing exposure pipeline."""

    def __init__(self) -> None:
        self.crawler = WebCrawler(tor_proxy=os.getenv("SENTINEL_TOR_PROXY"))
        self.matcher = DarkWebMatcher()

    async def crawl_targets(self) -> dict[str, int]:
        targets = await self._targets()
        pages = 0
        errors = 0
        for target in targets:
            try:
                results = await self.crawler.crawl(
                    str(target["url"]),
                    layer=str(target["layer"]),
                    respect_robots=bool(target.get("respect_robots", True)),
                    depth=int(target.get("max_depth") or 0),
                )
                for page in results:
                    await self._persist_page(target, page)
                    pages += 1
                await self._touch_target(str(target["id"]), "success")
            except Exception as exc:
                errors += 1
                await self._touch_target(str(target["id"]), f"failed:{type(exc).__name__}")
                logger.warning("web target failed id=%s", target.get("id"), exc_info=True)
        return {"targets": len(targets), "pages": pages, "errors": errors}

    async def _persist_page(self, target: dict[str, Any], page: WebPage) -> None:
        layer = str(target["layer"])
        severity = "critical" if page.credential_indicators or page.wallets else "high" if page.emails else "medium"
        row = {
            "target_id": str(target["id"]),
            "url": page.url[:2000],
            "content_hash": page.content_hash,
            "status_code": page.status_code,
            "content_type": page.content_type,
            "matched_terms": (["credential_indicator"] if page.credential_indicators else []) + (["wallet"] if page.wallets else []),
            "emails_found": list(page.emails),
            "urls_found": list(page.urls),
            "wallets_found": list(page.wallets),
            "credentials_found": page.credential_indicators,
            "severity": severity,
            "tenant_id": target.get("tenant_id"),
        }

        async def _insert():
            client = await supabase._ensure()
            return await client.table("web_crawl_pages").upsert(row, on_conflict="target_id,content_hash").execute()

        await supabase._retry(_insert, attempts=2)

        # Only emit indicators that can be safely represented by the existing
        # watchlist matcher. The page body and credential values never enter it.
        for email in page.emails[:50]:
            await self.matcher.process({
                "source_id": f"web_{layer}",
                "kind": "email",
                "matched_value": email,
                "context": f"Monitored identifier observed on configured {layer} source.",
                "severity": severity,
                "source_url": page.url,
                "metadata": {"exposure_layer": layer, "target_id": str(target["id"])},
            })
        for wallet in page.wallets[:20]:
            await self.matcher.process({
                "source_id": f"web_{layer}",
                "kind": "wallet",
                "matched_value": hashlib.sha256(wallet.encode()).hexdigest(),
                "context": f"Monitored wallet indicator observed on configured {layer} source.",
                "severity": severity,
                "source_url": page.url,
                "metadata": {"exposure_layer": layer, "target_id": str(target["id"]), "value_hashed": True},
            })

    async def query_deep(self, tenant_id: UUID, identifier: str) -> dict[str, Any]:
        """Query configured licensed intelligence providers without retaining secrets."""
        identifier = identifier.strip().lower()
        if not identifier or len(identifier) > 320:
            raise ValueError("invalid identifier")
        providers = [
            ("dehashed", os.getenv("SENTINEL_DEHASHED_EMAIL"), os.getenv("SENTINEL_DEHASHED_KEY")),
            ("intelx", None, os.getenv("SENTINEL_INTELX_KEY")),
            ("spycloud", None, os.getenv("SENTINEL_SPYCLOUD_KEY")),
        ]
        # Provider adapters are intentionally isolated behind a metadata-only
        # contract. No password, token, cookie, or combo-list value is returned.
        configured = [name for name, _account, key in providers if key]
        return {"tenant_id": str(tenant_id), "identifier": identifier, "configured_providers": configured, "hits": 0}

    async def _targets(self) -> list[dict[str, Any]]:
        async def _do():
            client = await supabase._ensure()
            return await client.table("web_crawl_targets").select("*").eq("enabled", True).execute()
        response = await supabase._retry(_do, attempts=2)
        return list(response.data or [])

    async def _touch_target(self, target_id: str, status: str) -> None:
        async def _do():
            client = await supabase._ensure()
            return await client.table("web_crawl_targets").update({"last_crawl_at": "now()", "last_status": status[:200]}).eq("id", target_id).execute()
        try:
            await supabase._retry(_do, attempts=1)
        except Exception:
            logger.warning("failed to update web target health id=%s", target_id, exc_info=True)
