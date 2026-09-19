from __future__ import annotations

import re
from typing import Any

from cyclothone.knowledge.intent import classify
from cyclothone.storage.supabase_client import supabase


class KnowledgeUnavailable(RuntimeError):
    pass


SYNONYMS: dict[str, tuple[str, ...]] = {
    "antivirus": ("endpoint", "edr", "detection", "malware"),
    "firewall": ("network", "fusion", "edge"),
    "phishing": ("scam", "email", "lens", "link"),
    "ransomware": ("honeynet", "twin", "recovery"),
    "spam": ("scam", "email", "link"),
    "leak": ("darkweb", "lens", "breach"),
    "hack": ("edr", "honeynet", "predict"),
    "deepfake": ("scam", "chauliodus", "voice"),
    "location": ("chauliodus", "gsma", "federation"),
    "banking": ("banking", "swift", "pci"),
    "compliance": ("zk", "compliance", "iso", "soc2", "gdpr"),
    "photo": ("chauliodus", "lens", "biometrics"),
    "voice": ("chauliodus", "scam", "biometrics"),
    "number": ("chauliodus", "gsma", "phone"),
    "drone": ("robotics", "physical", "fusion"),
    "hotel": ("physical", "fusion", "embed"),
    "fraud": ("banking", "scam", "chauliodus"),
    "insider": ("fusion", "twin", "physical"),
}


class KnowledgeSearch:
    async def search(self, query: str, limit: int = 30) -> dict[str, Any]:
        q = (query or "").strip()
        if not q:
            return {"intent": "unknown", "confidence": 0.0, "results": [], "count": 0, "grouped": []}
        if len(q) > 300:
            raise ValueError("query is too long")
        if not 1 <= limit <= 100:
            raise ValueError("limit out of range")

        intent = classify(q)
        expanded = self._expand(q)

        async def _do():
            client = await supabase._ensure()
            return await client.rpc("kg_search", {
                "p_query": expanded,
                "p_limit": min(limit * 2, 100),
            }).execute()

        try:
            response = await supabase._retry(_do, attempts=2)
        except Exception as exc:
            raise KnowledgeUnavailable("knowledge search unavailable") from exc

        results: list[dict[str, Any]] = []
        seen: set[str] = set()
        for row in response.data or []:
            node_id = str(row["node_id"])
            if node_id in seen:
                continue
            seen.add(node_id)
            results.append({
                "node_id": node_id,
                "kind": row["kind"],
                "label": row["label"],
                "summary": row["summary"],
                "service_id": row["service_id"],
                "deep_link": row["deep_link"],
                "score": float(row.get("score") or 0.0),
            })
            if len(results) >= limit:
                break

        if intent.kind != "unknown":
            results.sort(key=lambda row: (
                0 if row["kind"] == intent.kind else 1,
                -row["score"],
                row["node_id"],
            ))

        grouped: dict[str, list[dict[str, Any]]] = {}
        for result in results:
            grouped.setdefault(result["kind"], []).append(result)

        return {
            "intent": intent.kind,
            "confidence": intent.confidence,
            "matched": list(intent.matched),
            "count": len(results),
            "results": results,
            "grouped": grouped,
            "suggested_actions": self._suggested_actions(intent.kind, results),
        }

    @staticmethod
    def _expand(query: str) -> str:
        terms = re.findall(r"[a-z0-9][a-z0-9_-]{0,63}", query.lower())
        expanded: list[str] = []
        seen: set[str] = set()
        for term in (*terms, *(syn for t in terms for syn in SYNONYMS.get(t, ()))):
            if term not in seen:
                seen.add(term)
                expanded.append(term)
        # OR semantics keep synonym expansion from accidentally requiring every term.
        return " OR ".join(expanded)

    @staticmethod
    def _suggested_actions(intent: str, results: list[dict[str, Any]]) -> list[dict[str, str]]:
        if intent == "api":
            return [
                {"label": f"Open API — {row['label']}", "url": row["deep_link"]}
                for row in results if row["kind"] == "api"
            ][:3]
        if intent == "guide":
            return [
                {"label": f"Start guide — {row['label']}", "url": row["deep_link"]}
                for row in results if row["kind"] == "guide"
            ][:3]
        if intent == "support":
            return [{"label": "Open a ticket", "url": "/support/new"}]
        return []
