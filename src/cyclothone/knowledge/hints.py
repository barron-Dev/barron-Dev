from __future__ import annotations

from typing import Any

from cyclothone.storage.supabase_client import supabase
from cyclothone.knowledge.search import KnowledgeUnavailable


class ContextHints:
    async def for_page(self, route: str, audience: str = "client") -> dict[str, Any]:
        route = (route or "").strip()
        audience = (audience or "").strip()
        if not 1 <= len(route) <= 500:
            raise ValueError("route is invalid")
        if audience not in {"visitor", "client", "partner", "developer", "admin"}:
            raise ValueError("audience is invalid")

        async def _do():
            client = await supabase._ensure()
            return await (
                client.table("context_hints")
                .select("element_key,title,body_md,guide_slug,doc_url,api_url,priority")
                .eq("page_route", route)
                .contains("audience", [audience])
                .order("priority")
                .order("element_key")
                .limit(500)
                .execute()
            )

        try:
            response = await supabase._retry(_do, attempts=2)
        except Exception as exc:
            raise KnowledgeUnavailable("context hints unavailable") from exc
        return {str(row["element_key"]): row for row in response.data or []}
