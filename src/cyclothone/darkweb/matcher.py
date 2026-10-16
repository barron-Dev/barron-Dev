from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from cyclothone.storage.supabase_client import supabase

logger = logging.getLogger(__name__)
SEVERITY = {"medium": 0, "high": 1, "critical": 2}
LAYERS = {"surface", "deep", "dark"}
SCOPES = {"global", "watchlist"}


def _digest(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()


def _content_fingerprint(
    finding: dict[str, Any],
    tenant_id: str | None = None,
    watchlist_id: str | None = None,
) -> str:
    """Stable identity for evidence; volatile provider metadata must not create duplicate findings."""
    identity = {
        "source_id": str(finding.get("source_id") or "").strip(),
        "kind": str(finding.get("kind") or "").strip().lower(),
        "matched_value": str(finding.get("matched_value") or "").strip().lower(),
        "source_url": str(finding.get("source_url") or "").strip() or None,
    }
    if tenant_id is not None or watchlist_id is not None:
        if not tenant_id or not watchlist_id:
            raise ValueError("tenant and watchlist are both required for a scoped fingerprint")
        identity["tenant_id"] = str(tenant_id)
        identity["watchlist_id"] = str(watchlist_id)
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


class DarkWebMatcher:
    """Persist findings with explicit global or exact-watchlist matching semantics."""

    async def process(
        self,
        finding: dict[str, Any],
        *,
        scope: str = "global",
        tenant_id: str | None = None,
        watchlist_id: str | None = None,
        persist_unmatched_global: bool = False,
    ) -> dict[str, Any]:
        if scope not in SCOPES:
            return self._result("invalid_scope", errors=1)
        if scope == "watchlist" and (not tenant_id or not watchlist_id):
            return self._result("scope_required", errors=1)
        if scope == "global" and (tenant_id is not None or watchlist_id is not None):
            return self._result("scope_mismatch", errors=1)

        try:
            source_id = str(finding["source_id"]).strip()
            kind = str(finding["kind"]).strip().lower()
            value = str(finding["matched_value"]).strip().lower()
        except (KeyError, TypeError, ValueError):
            return self._result("invalid_finding", errors=1)
        if not source_id or not kind or not value:
            return self._result("invalid_finding", errors=1)

        metadata = finding.get("metadata") or {}
        if not isinstance(metadata, dict):
            return self._result("invalid_finding", errors=1)
        layer = str(finding.get("exposure_layer") or metadata.get("exposure_layer") or "surface").lower()
        if layer not in LAYERS:
            logger.warning("unknown dark web exposure layer=%s", layer)
            return self._result("invalid_layer", errors=1)

        try:
            if scope == "watchlist":
                matches = await self._lookup_scoped(kind, value, str(tenant_id), str(watchlist_id))
                if not matches:
                    return self._result("no_watchlist_match")
            else:
                matches = await self._lookup_global(kind, value)
        except Exception:
            logger.exception("dark web watchlist lookup failed scope=%s kind=%s", scope, kind)
            return self._result("lookup_failed", errors=1)

        if not matches:
            if not persist_unmatched_global:
                return self._result("unmatched_not_persisted")
            result = await self._record(finding, None, None, layer=layer, tenant_scoped=False)
            if result.get("error"):
                return self._result("persistence_failed", errors=1)
            return self._result("unmatched_candidate_persisted", persisted=1)

        alerts = errors = persisted = 0
        for watch in matches:
            severity = max_severity(str(watch.get("severity", "high")), str(finding.get("severity", "medium")))
            result = await self._record(
                finding,
                str(watch["tenant_id"]),
                str(watch["id"]),
                severity,
                layer=layer,
                tenant_scoped=True,
            )
            if result.get("error"):
                errors += 1
                continue
            persisted += int(bool(result.get("finding_id")))
            alerts += int(bool(result.get("alert_id")))
        status = "persisted" if errors == 0 else ("partial_persistence_failure" if persisted else "persistence_failed")
        return self._result(status, matched=len(matches), persisted=persisted, alerts=alerts, errors=errors)

    async def _lookup_scoped(self, kind: str, value: str, tenant_id: str, watchlist_id: str) -> list[dict[str, Any]]:
        digest = _digest(value)

        async def _do():
            client = await supabase._ensure()
            watch_response = await (
                client.table("dw_watchlist")
                .select("id,tenant_id,kind,severity,value_hash")
                .eq("id", watchlist_id)
                .eq("tenant_id", tenant_id)
                .limit(1)
                .execute()
            )
            watches = list(watch_response.data or [])
            if not watches:
                return {"status": "watchlist_scope_invalid", "rows": []}
            watch = watches[0]
            if str(watch.get("kind", "")).lower() != kind:
                return {"status": "watchlist_kind_mismatch", "rows": []}
            if str(watch.get("value_hash", "")).lower() == digest:
                return {"status": "ok", "rows": [watch]}
            alias_response = await (
                client.table("dw_watch_aliases")
                .select("watchlist_id,tenant_id,kind,alias_hash")
                .eq("watchlist_id", watchlist_id)
                .eq("tenant_id", tenant_id)
                .eq("kind", kind)
                .eq("alias_hash", digest)
                .limit(1)
                .execute()
            )
            aliases = list(alias_response.data or [])
            return {"status": "ok", "rows": [watch] if aliases else []}

        response = await supabase._retry(_do, attempts=2)
        payload = response.data if hasattr(response, "data") else response
        if not isinstance(payload, dict) or "rows" not in payload:
            raise RuntimeError("scoped watchlist lookup returned an invalid response")
        if payload.get("status") in {"watchlist_scope_invalid", "watchlist_kind_mismatch"}:
            raise ValueError(str(payload["status"]))
        return list(payload["rows"] or [])

    async def _lookup_global(self, kind: str, value: str) -> list[dict[str, Any]]:
        digest = _digest(value)

        async def _do():
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
                    .eq("kind", kind)
                    .limit(1)
                    .execute()
                )
                if watch.data:
                    rows.append(watch.data[0])
                    seen.add(watch_id)
            return rows

        response = await supabase._retry(_do, attempts=2)
        payload = response.data if hasattr(response, "data") else response
        return list(payload or [])

    async def _record(
        self,
        finding: dict[str, Any],
        tenant_id: str | None,
        watchlist_id: str | None,
        severity: str | None = None,
        layer: str = "surface",
        tenant_scoped: bool = False,
    ) -> dict[str, Any]:
        metadata = dict(finding.get("metadata") or {})
        metadata["exposure_layer"] = layer
        if tenant_scoped and (not tenant_id or not watchlist_id):
            return {"error": "scope_required"}
        content_hash = _content_fingerprint(
            finding,
            tenant_id if tenant_scoped else None,
            watchlist_id if tenant_scoped else None,
        )

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
            data = response.data if hasattr(response, "data") else response
            row = (data or [{}])[0] if isinstance(data, list) else (data or {})
            if not isinstance(row, dict) or not row.get("finding_id"):
                return {"error": "rpc_missing_finding_id"}
            return {"finding_id": row.get("finding_id"), "alert_id": row.get("alert_id"), "detection_id": row.get("detection_id")}
        except Exception as exc:
            logger.exception("dark web finding ingestion failed source=%s", finding.get("source_id"))
            return {"error": type(exc).__name__}

    @staticmethod
    def _result(status: str, *, matched: int = 0, persisted: int = 0, alerts: int = 0, errors: int = 0) -> dict[str, Any]:
        return {"status": status, "matched": matched, "persisted": persisted, "alerts": alerts, "errors": errors}


def max_severity(a: str, b: str) -> str:
    """Return the higher known severity, failing closed to the known medium baseline."""
    left = a.strip().lower()
    right = b.strip().lower()
    left_known = left if left in SEVERITY else "medium"
    right_known = right if right in SEVERITY else "medium"
    return left_known if SEVERITY[left_known] >= SEVERITY[right_known] else right_known
