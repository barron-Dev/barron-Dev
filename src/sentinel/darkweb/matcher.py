from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from sentinel.storage.supabase_client import supabase

logger = logging.getLogger(__name__)
SEVERITY = {"medium": 0, "high": 1, "critical": 2}
LAYERS = {"surface", "deep", "dark"}


class DarkWebMatcher:
    async def process(self, finding: dict[str, Any]) -> dict[str, Any]:
        kind = str(finding["kind"])
        value = str(finding["matched_value"]).strip().lower()
        layer = str(finding.get("exposure_layer") or (finding.get("metadata") or {}).get("exposure_layer") or "surface").lower()
        if layer not in LAYERS:
            logger.warning("unknown darkweb exposure layer=%s", layer)
            return {"matched": 0, "alerts": 0, "errors": 1}
        if not value:
            return {"matched": 0, "alerts": 0, "errors": 0}
        digest = hashlib.sha256(value.encode()).hexdigest()

        async def _lookup():
            client = await supabase._ensure()
            exact = await (
                client.table("dw_watchlist")
                .select("id,tenant_id,kind,severity")
                .eq("kind", kind)
                .eq("value_hash", digest)
                .execute()
            )
            rows = list(exact.data or [])
            seen = {str(row["id"]) for row in rows}
            aliases = await (
                client.table("dw_watch_aliases")
                .select("watchlist_id,tenant_id,kind")
                .eq("kind", kind)
                .eq("alias_hash", digest)
                .execute()
            )
            for alias in aliases.data or []:
                watch_id = str(alias["watchlist_id"])
                if watch_id in seen:
                    continue
                watch = await (
                    client.table("dw_watchlist")
                    .select("id,tenant_id,kind,severity")
                    .eq("id", watch_id)
                    .eq("tenant_id", str(alias["tenant_id"]))
                    .limit(1)
                    .execute()
                )
                if watch.data:
                    rows.append(watch.data[0])
                    seen.add(watch_id)
            return rows

        try:
            response = await supabase._retry(_lookup, attempts=2)
            matches = list(response.data or []) if hasattr(response, "data") else list(response or [])
        except Exception:
            logger.exception("dark web watchlist lookup failed for kind=%s", kind)
            return {"matched": 0, "alerts": 0, "errors": 1}

        alerts = 0
        errors = 0
        if not matches:
            result = await self._record(finding, None, None, layer=layer)
            return {"matched": 0, "alerts": 0, "errors": int(bool(result.get("error")))}
        for watch in matches:
            result = await self._record(
                finding,
                str(watch["tenant_id"]),
                str(watch["id"]),
                max_severity(str(watch.get("severity", "high")), str(finding.get("severity", "medium"))),
                layer=layer,
            )
            if result.get("alert_id"):
                alerts += 1
            if result.get("error"):
                errors += 1
        return {"matched": len(matches), "alerts": alerts, "errors": errors}

    async def _record(
        self,
        finding: dict[str, Any],
        tenant_id: str | None,
        watchlist_id: str | None,
        severity: str | None = None,
        layer: str = "surface",
    ) -> dict[str, Any]:
        metadata = dict(finding.get("metadata") or {})
        metadata["exposure_layer"] = layer
        content_key = f"{finding['source_id']}:{finding['kind']}:{str(finding['matched_value']).strip().lower()}:{json.dumps(metadata, sort_keys=True, separators=(',', ':'))}"
        content_hash = hashlib.sha256(content_key.encode()).hexdigest()

        async def _do():
            client = await supabase._ensure()
            return await client.rpc("record_dw_finding", {
                "p_source_id": finding["source_id"],
                "p_content_hash": content_hash,
                "p_kind": finding["kind"],
                "p_matched_value": str(finding["matched_value"]).strip().lower(),
                "p_context": finding.get("context"),
                "p_severity": severity or finding.get("severity", "medium"),
                "p_source_url": finding.get("source_url"),
                "p_metadata": metadata,
                "p_tenant_id": tenant_id,
                "p_watchlist_id": watchlist_id,
            }).execute()

        try:
            response = await supabase._retry(_do, attempts=2)
            row = (response.data or [{}])[0] if isinstance(response.data, list) else (response.data or {})
            return {"finding_id": row.get("finding_id"), "alert_id": row.get("alert_id"), "detection_id": row.get("detection_id")}
        except Exception as exc:
            logger.exception("dark web finding ingestion failed source=%s", finding.get("source_id"))
            return {"error": type(exc).__name__}


def max_severity(a: str, b: str) -> str:
    """Return the higher known severity, failing closed to the known medium baseline."""
    left = a.strip().lower()
    right = b.strip().lower()
    left_known = left if left in SEVERITY else "medium"
    right_known = right if right in SEVERITY else "medium"
    return left_known if SEVERITY[left_known] >= SEVERITY[right_known] else right_known
