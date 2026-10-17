from __future__ import annotations
from datetime import UTC, datetime
from typing import Any
from .parse_target import normalize_target, parse_target

TERMINAL = {"resolved", "succeeded", "completed"}
SERVICE_MAP = {
    "dark_web_monitoring": ("dark_web_exposure", "Dark web exposure assessment"),
    "cybersecurity_assessment": ("public_surface_assessment", "Public surface assessment"),
}

def _sources(result: dict[str, Any]) -> list[dict[str, Any]]:
    raw = result.get("source_results")
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, dict)]
    raw = result.get("sources")
    if isinstance(raw, list):
        # The current DWM handler appends source IDs only after the pull succeeds.
        return [{"name": str(x), "status": "succeeded", "attempted": True}
                for x in raw if isinstance(x, str) and x.strip()]
    if result.get("method") == "bounded passive public HTTP assessment" and result.get("status_code") is not None:
        return [{"name": "public_http", "status": "succeeded", "attempted": True}]
    return []

def _attempted(source: dict[str, Any]) -> bool:
    if source.get("attempted") is True:
        return True
    return str(source.get("status", "")).lower() in {
        "success", "succeeded", "partial", "failed", "unavailable",
        "rate_limited", "timeout", "error",
    }

def _findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    raw = result.get("findings")
    if not isinstance(raw, list):
        raw = result.get("alert_records")
    return [x for x in raw if isinstance(x, dict)] if isinstance(raw, list) else []

async def materialize_claims_for_request(request_id: str, *, sb: Any) -> list[dict[str, Any]]:
    """Write claims only from persisted terminal result payloads and explicit execution evidence."""
    if sb is None:
        raise ValueError("trusted service-role Supabase client required")
    response = await (sb.table("service_requests")
        .select("id,organization_id,service_key,status,description,target,target_type,result,completed_at,updated_at")
        .eq("id", request_id).maybe_single().execute())
    row = getattr(response, "data", None)
    if not isinstance(row, dict) or str(row.get("status", "")).lower() not in TERMINAL:
        return []
    service_key = str(row.get("service_key") or "").lower()
    mapped = SERVICE_MAP.get(service_key)
    if not mapped or not row.get("organization_id"):
        return []
    result = row.get("result")
    if not isinstance(result, dict):
        return []
    sources = _sources(result)
    attempted = [s for s in sources if _attempted(s)]
    if not attempted:
        return []
    target = str(row.get("target") or "").strip() or parse_target(row.get("description"))
    if not target:
        return []
    key = normalize_target(target)
    if not key:
        return []
    findings = _findings(result)
    unavailable = sum(str(s.get("status", "")).lower() in {
        "unavailable", "failed", "rate_limited", "timeout", "error"
    } for s in attempted)
    severities = [str(x.get("severity", "")).lower() for x in findings]
    severity = ("critical" if "critical" in severities else "high" if "high" in severities
                else "medium" if "medium" in severities else "low" if "low" in severities
                else "info" if findings else "unknown")
    coverage = ("partial" if unavailable or len(attempted) < 2
                else "attention" if findings else "verified_partial")
    now = row.get("completed_at") or row.get("updated_at") or datetime.now(UTC).isoformat()
    evidence = {
        "request_id": str(row["id"]),
        "source_outcomes": [{"name": str(s.get("name", "unknown"))[:100],
                             "status": str(s.get("status", "unknown"))[:40],
                             "attempted": True} for s in attempted[:200]],
        "sources_checked": len(attempted),
        "sources_unavailable": unavailable,
        "finding_count": len(findings),
        "provenance": "persisted terminal service request result",
    }
    rpc = await sb.rpc("upsert_security_claim", {
        "p_organization_id": row["organization_id"],
        "p_target_key": key,
        "p_target_kind": str(row.get("target_type") or "domain"),
        "p_claim_type": mapped[0],
        "p_coverage_status": coverage,
        "p_severity": severity,
        "p_title": mapped[1],
        "p_statement": (f"Persisted execution recorded {len(findings)} finding(s) across "
                        f"{len(attempted)} attempted source outcome(s); "
                        f"{unavailable} outcome(s) were unavailable or failed. Coverage: {coverage}."),
        "p_confidence": None,
        "p_sources_checked": len(attempted),
        "p_sources_unavailable": unavailable,
        "p_finding_count": len(findings),
        "p_high_finding_count": sum(s in {"high", "critical"} for s in severities),
        "p_evidence": evidence,
        "p_origin_service_key": service_key,
        "p_origin_request_id": row["id"],
        "p_observed_at": now,
    }).execute()
    data = getattr(rpc, "data", None)
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    return [data] if isinstance(data, dict) else []
