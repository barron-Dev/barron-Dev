from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from cyclothone.knowledge.search import KnowledgeUnavailable
from cyclothone.storage.supabase_client import supabase


class Recommender:
    def __init__(self, tenant_id: UUID, user_id: UUID | None = None) -> None:
        self.tenant_id = tenant_id
        self.user_id = user_id

    async def next_best(self, context: dict[str, Any], limit: int = 4) -> list[dict[str, Any]]:
        if not 1 <= limit <= 20:
            raise ValueError("limit out of range")
        if not isinstance(context, dict):
            raise ValueError("context must be an object")

        rules = await self._rules()
        impressions = await self._recent_impressions()

        now = datetime.now(UTC)
        scored: list[tuple[float, dict[str, Any]]] = []
        for rule in rules:
            last = impressions.get(str(rule["id"]))
            if last and now - last < timedelta(hours=24):
                continue
            if not self._matches(rule["condition"], context):
                continue
            score = min(1.0, float(rule["base_score"]) + self._priority_boost(int(rule["priority"])))
            scored.append((score, rule))

        scored.sort(key=lambda pair: (-pair[0], int(pair[1]["priority"]), str(pair[1]["id"])))
        selected = scored[:limit]

        for score, rule in selected:
            await self._record_impression(UUID(str(rule["id"])))

        return [{
            "id": str(rule["id"]),
            "kind": rule["kind"],
            "title": rule["title"],
            "body_md": rule["body_md"],
            "cta_label": rule["cta_label"],
            "cta_url": rule["cta_url"],
            "score": score,
        } for score, rule in selected]

    @staticmethod
    def _priority_boost(priority: int) -> float:
        return max(0.0, min(0.2, (100 - priority) / 500.0))

    @staticmethod
    def _matches(condition: dict[str, Any], context: dict[str, Any]) -> bool:
        if not isinstance(condition, dict) or not condition:
            return False
        if "all" in condition:
            values = condition["all"]
            return isinstance(values, list) and all(Recommender._single(item, context) for item in values)
        if "any" in condition:
            values = condition["any"]
            return isinstance(values, list) and any(Recommender._single(item, context) for item in values)
        return Recommender._single(condition, context)

    @staticmethod
    def _single(condition: Any, context: dict[str, Any]) -> bool:
        if not isinstance(condition, dict):
            return False
        field = condition.get("field")
        op = condition.get("op", "eq")
        expected = condition.get("value")
        if not isinstance(field, str) or len(field) > 120:
            return False
        actual = context.get(field)
        try:
            if op == "eq": return actual == expected
            if op == "ne": return actual != expected
            if op in {"gt", "gte", "lt", "lte"}:
                a, b = float(actual), float(expected)
                return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[op]
            if op == "in": return actual in (expected if isinstance(expected, list) else [])
            if op == "contains": return expected in (actual if isinstance(actual, list) else [])
            if op == "not_contains": return expected not in (actual if isinstance(actual, list) else [])
        except (TypeError, ValueError):
            return False
        return False

    async def _rules(self) -> list[dict[str, Any]]:
        async def _do():
            client = await supabase._ensure()
            return await (
                client.table("recommendation_rules")
                .select("id,condition,kind,title,body_md,cta_label,cta_url,base_score,priority")
                .eq("enabled", True)
                .order("priority")
                .order("id")
                .limit(1000)
                .execute()
            )
        try:
            response = await supabase._retry(_do, attempts=2)
        except Exception as exc:
            raise KnowledgeUnavailable("recommendation rules unavailable") from exc
        return list(response.data or [])

    async def _recent_impressions(self) -> dict[str, datetime]:
        since = (datetime.now(UTC) - timedelta(days=2)).isoformat()

        async def _do():
            client = await supabase._ensure()
            return await (
                client.table("recommendation_impressions")
                .select("rule_id,shown_at")
                .eq("tenant_id", str(self.tenant_id))
                .gte("shown_at", since)
                .order("shown_at", desc=True)
                .limit(2000)
                .execute()
            )

        try:
            response = await supabase._retry(_do, attempts=2)
        except Exception as exc:
            raise KnowledgeUnavailable("recommendation history unavailable") from exc

        latest: dict[str, datetime] = {}
        for row in response.data or []:
            timestamp = datetime.fromisoformat(str(row["shown_at"]).replace("Z", "+00:00"))
            key = str(row["rule_id"])
            if key not in latest or timestamp > latest[key]:
                latest[key] = timestamp
        return latest

    async def _record_impression(self, rule_id: UUID) -> None:
        async def _do():
            return await supabase.rpc("knowledge_record_impression", {
                "p_tenant": str(self.tenant_id),
                "p_user": str(self.user_id) if self.user_id else None,
                "p_rule": str(rule_id),
            })

        try:
            await supabase._retry(_do, attempts=2)
        except Exception as exc:
            # Do not return recommendations that were silently claimed as shown.
            raise KnowledgeUnavailable("recommendation audit unavailable") from exc
