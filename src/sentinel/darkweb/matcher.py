from __future__ import annotations

import hashlib
import json
from typing import Any

from sentinel.storage.supabase_client import supabase

SEVERITY = {"medium": 0, "high": 1, "critical": 2}

class DarkWebMatcher:
    async def process(self, finding: dict[str, Any]) -> dict[str, Any]:
        kind = str(finding["kind"])
        value = str(finding["matched_value"]).strip().lower()
        if not value:
            return {"matched": 0, "alerts": 0}
        digest = hashlib.sha256(value.encode()).hexdigest()

        async def _lookup():
            client = await supabase._ensure()
            return await client.table("dw_watchlist").select("id,tenant_id,kind,severity").eq("kind", kind).eq("value_hash", digest).execute()
        matches = list((await supabase._retry(_lookup, attempts=2)).data or [])
        alerts = 0
        if not matches:
            await self._record(finding, None, None)
            return {"matched": 0, "alerts": 0}
        for watch in matches:
            result = await self._record(finding, str(watch["tenant_id"]), str(watch["id"]), max_severity(str(watch.get("severity", "high")), str(finding.get("severity", "medium"))))
            if result.get("alert_id"):
                alerts += 1
        return {"matched": len(matches), "alerts": alerts}

    async def _record(self, finding: dict[str, Any], tenant_id: str | None, watchlist_id: str | None, severity: str | None = None) -> dict[str, Any]:
        content_key = f"{finding['source_id']}:{finding['kind']}:{str(finding['matched_value']).strip().lower()}:{json.dumps(finding.get('metadata') or {}, sort_keys=True, separators=(',', ':'))}"
        content_hash = hashlib.sha256(content_key.encode()).hexdigest()
        async def _do():
            client = await supabase._ensure()
            return await client.rpc("record_dw_finding", {
                "p_source_id": finding["source_id"], "p_content_hash": content_hash,
                "p_kind": finding["kind"], "p_matched_value": str(finding["matched_value"]).strip().lower(),
                "p_context": finding.get("context"), "p_severity": severity or finding.get("severity", "medium"),
                "p_source_url": finding.get("source_url"), "p_metadata": finding.get("metadata") or {},
                "p_tenant_id": tenant_id, "p_watchlist_id": watchlist_id,
            }).execute()
        try:
            response = await supabase._retry(_do, attempts=2)
            row = (response.data or [{}])[0] if isinstance(response.data, list) else (response.data or {})
            return {"finding_id": row.get("finding_id"), "alert_id": row.get("alert_id"), "detection_id": row.get("detection_id")}
        except Exception:
            return {}


def max_severity(a: str, b: str) -> str:
    return a if SEVERITY.get(a, 0) >= SEVERITY.get(b, 0) else b
