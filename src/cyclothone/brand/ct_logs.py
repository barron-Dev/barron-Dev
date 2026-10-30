from __future__ import annotations

import hashlib
import json
import logging

import httpx

from cyclothone.brand.similarity import combined_similarity
from cyclothone.storage.supabase_client import supabase

logger = logging.getLogger(__name__)


class CTLogMonitor:
    BASE = "https://crt.sh"

    async def query_keyword(self, keyword: str, timeout: float = 30) -> list[dict] | None:
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(
                    self.BASE + "/",
                    params={"q": f"%{keyword}%", "output": "json"},
                    headers={"user-agent": "CyclothoneBrand/1.0"},
                )
                if response.status_code != 200:
                    return None
                payload = response.json()
                return payload if isinstance(payload, list) else None
        except Exception:
            logger.warning("certificate transparency source unavailable", exc_info=True)
            return None

    async def match_brands(self) -> dict:
        brands = await self._brands()
        stats = {
            "brands": len(brands),
            "source_queries": 0,
            "source_unavailable": 0,
            "candidate_matches": 0,
            "recorded_candidates": 0,
            "persistence_failures": 0,
            "verified_threats": 0,
        }
        for brand in brands:
            keywords = set(brand.get("keywords") or [])
            keywords.add(brand["primary_domain"].split(".")[0])
            seen: set[str] = set()
            for keyword in list(keywords)[:5]:
                stats["source_queries"] += 1
                entries = await self.query_keyword(keyword)
                if entries is None:
                    stats["source_unavailable"] += 1
                    continue
                for entry in entries[:500]:
                    for domain in self._extract_sans(entry):
                        if (
                            domain in seen
                            or domain == brand["primary_domain"]
                            or any(
                                domain.endswith("." + owned)
                                for owned in brand.get("domains") or []
                            )
                        ):
                            continue
                        seen.add(domain)
                        similarity = combined_similarity(
                            domain, brand["primary_domain"]
                        )
                        if similarity < float(brand.get("similarity_min", 0.75)):
                            continue
                        stats["candidate_matches"] += 1
                        kind = self._classify(domain, brand["primary_domain"])
                        severity = self._severity(similarity, kind)
                        source_record = json.dumps(
                            entry, sort_keys=True, separators=(",", ":")
                        ).encode()
                        persisted = await self._record(
                            brand["tenant_id"],
                            brand["id"],
                            kind,
                            domain,
                            "https://" + domain,
                            "web",
                            similarity,
                            severity,
                            {
                                "issuer": entry.get("issuer_name"),
                                "certificate_id": entry.get("id"),
                                "source": "certificate_transparency",
                                "evidence_stage": "certificate_observation",
                                "verification_state": "candidate",
                                "evidence_sha256": hashlib.sha256(source_record).hexdigest(),
                                "tls_identity_verified": False,
                                "page_content_inspected": False,
                            },
                        )
                        if persisted:
                            stats["recorded_candidates"] += 1
                        else:
                            stats["persistence_failures"] += 1
        return stats

    @staticmethod
    def _extract_sans(entry: dict) -> list[str]:
        output = []
        values = [entry.get("common_name", ""), *(entry.get("name_value") or "").split("\n")]
        for value in values:
            domain = value.strip().lower()
            if domain and domain not in output:
                output.append(domain)
        return output

    @staticmethod
    def _classify(candidate: str, primary: str) -> str:
        if candidate.startswith("xn--"):
            return "homoglyph"
        candidate_base = candidate.split(".")[0]
        primary_base = primary.split(".")[0]
        if candidate_base == primary_base:
            return "tld_swap"
        if "-" in candidate_base:
            return "combosquat"
        return "typosquat"

    @staticmethod
    def _severity(similarity: float, kind: str) -> str:
        if similarity >= 0.95 or kind == "homoglyph":
            return "critical"
        if similarity >= 0.85:
            return "high"
        return "medium"

    async def _record(
        self, tenant_id, brand_id, kind, identifier, url, platform,
        similarity, severity, metadata
    ) -> bool:
        async def query():
            client = await supabase._ensure()
            return await client.rpc(
                "record_brand_threat",
                {
                    "p_tenant": tenant_id,
                    "p_brand": brand_id,
                    "p_kind": kind,
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
            logger.warning("brand CT candidate persistence failed", exc_info=True)
            return False

    async def _brands(self):
        async def query():
            return await (
                await supabase._ensure()
            ).table("brands").select("*").eq("enabled", True).eq(
                "monitor_ct_logs", True
            ).execute()

        try:
            return list((await supabase._retry(query, attempts=2)).data or [])
        except Exception:
            logger.exception("brand CT configuration query failed")
            return []
