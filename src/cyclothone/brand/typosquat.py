from __future__ import annotations

import asyncio
import socket

from cyclothone.brand.permutations import generate_permutations
from cyclothone.brand.similarity import combined_similarity
from cyclothone.storage.supabase_client import supabase


class TyposquatScanner:
    CONCURRENCY = 100

    async def scan_brand(self, brand):
        perms = generate_permutations(brand["primary_domain"], 3000)
        sem = asyncio.Semaphore(self.CONCURRENCY)
        stats = {"checked": 0, "resolved": 0, "threats": 0}

        async def check(permutation, technique):
            async with sem:
                stats["checked"] += 1
                if not await _resolves(permutation):
                    return
                stats["resolved"] += 1
                similarity = combined_similarity(
                    permutation, brand["primary_domain"]
                )
                kind = self._classify(technique)
                severity = (
                    "critical"
                    if similarity >= 0.92
                    else "high"
                    if similarity >= 0.82
                    else "medium"
                    if similarity >= 0.72
                    else "low"
                )
                await self._record(
                    brand["tenant_id"],
                    brand["id"],
                    kind,
                    permutation,
                    "https://" + permutation,
                    similarity,
                    severity,
                    {"technique": technique, "source": "typosquat"},
                )
                stats["threats"] += 1

        await asyncio.gather(
            *(check(permutation, technique) for permutation, technique in perms),
            return_exceptions=True,
        )
        return stats

    @staticmethod
    def _classify(technique):
        if technique == "homoglyph":
            return "homoglyph"
        if technique in ("combosquat", "hyphenation"):
            return "combosquat"
        if technique == "tld_swap":
            return "tld_swap"
        return "typosquat"

    async def _record(self, tenant, brand, kind, identifier, url, similarity, severity, metadata):
        async def query():
            client = await supabase._ensure()
            return await client.rpc(
                "record_brand_threat",
                {
                    "p_tenant": tenant,
                    "p_brand": brand,
                    "p_kind": kind,
                    "p_identifier": identifier,
                    "p_url": url,
                    "p_platform": "web",
                    "p_similarity": similarity,
                    "p_severity": severity,
                    "p_metadata": metadata,
                },
            ).execute()

        try:
            await supabase._retry(query, attempts=2)
        except Exception:
            pass


async def _resolves(domain):
    loop = asyncio.get_running_loop()
    try:
        return bool(
            await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(
                    domain, None, proto=socket.IPPROTO_TCP
                ),
            )
        )
    except Exception:
        return False
