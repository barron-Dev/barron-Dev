from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from cyclothone.identity_graph import canonicalize, identifier_hash

_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|cookie|authorization)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?i)\b(bearer)\s+[a-z0-9._~+/-]+=*"),
)
_KIND_TO_ENTITY = {
    "domain": "domain", "email": "email", "username": "username",
    "company_name": "organization", "phone": "phone", "ip": "ip_address",
    "executive_name": "person", "wallet": "breach_record",
    "api_key_hash": "breach_record", "employee_id": "breach_record",
    "customer_id": "breach_record",
}
_SUPPORTED_MODULES = {"darkweb", "breach", "code", "infra", "social"}
_MODULE_SOURCE_TOKENS = {
    "darkweb": ("darkweb", "dark_web", "ransomwatch", "pastebin", "telegram_public"),
    "breach": ("breach", "hibp", "xposedornot", "leak_lookup", "hudsonrock"),
    "code": ("github", "code_search"),
    "infra": ("shodan", "censys", "virustotal", "internetdb"),
    "social": ("social", "maigret", "telegram_public"),
}


def _source_matches_module(source: dict[str, Any], module: str) -> bool:
    searchable = " ".join(str(source.get(key) or "") for key in ("id", "name", "kind", "web_layer")).casefold()
    return any(token in searchable for token in _MODULE_SOURCE_TOKENS[module])


def normalize_target(kind: str, value: str) -> str:
    """Canonicalize a customer-authorized watch target; never perform fuzzy matching."""
    normalized_kind = kind.strip().lower()
    entity_type = _KIND_TO_ENTITY.get(normalized_kind)
    if not entity_type:
        raise ValueError("unsupported_query_type")
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise ValueError("invalid_query_value")
    return canonicalize(entity_type, value)


def redact_summary(value: Any, limit: int = 600) -> str | None:
    if value is None:
        return None
    text = str(value)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(lambda match: match.group(1) + "=[REDACTED]", text)
    return text[:limit]


def build_integration_matrix(sources: list[dict[str, Any]], *, evidence_count: int) -> list[dict[str, Any]]:
    """Report observed stages honestly; unknown stages remain unknown, never inferred green."""
    rows: list[dict[str, Any]] = []
    for module in sorted(_SUPPORTED_MODULES):
        relevant = [row for row in sources if _source_matches_module(row, module)]
        enabled = [row for row in relevant if row.get("enabled") is True]
        successful = [row for row in enabled if row.get("last_status") == "ok" and row.get("last_pull_at")]
        rows.append({
            "module": module,
            "configured": bool(relevant),
            "enabled_sources": len(enabled),
            "authenticated": "unknown",
            "source_reachable": "not_probed",
            "last_collection_successful": bool(successful),
            "records_normalized": "unknown",
            "results_persisted": evidence_count > 0 if module == "darkweb" else "unknown",
            "evidence_provenance_stored": "unknown",
            "tenant_isolation_enforced": True,
            "automated_tests_pass": "not_verified",
            "customer_ui_receives_results": "not_verified",
            "production_e2e_verified": False,
            "last_success_at": max((str(row.get("last_pull_at")) for row in successful), default=None),
            "blocker": "live source reachability has not been probed" if relevant else "no source configured for this module",
        })
    return rows


def build_report(*, target_kind: str, canonical_target: str, watch_id: str, findings: list[dict[str, Any]], sources: list[dict[str, Any]], requested_modules: list[str]) -> dict[str, Any]:
    safe_findings: list[dict[str, Any]] = []
    for row in findings:
        safe_findings.append({
            "id": str(row.get("id") or ""),
            "source_id": str(row.get("source_id") or "unknown"),
            "kind": str(row.get("kind") or "unknown"),
            "matched_value": redact_summary(row.get("matched_value"), 300),
            "summary": redact_summary(row.get("context"), 600),
            "severity": str(row.get("severity") or "unknown").lower(),
            "source_url": row.get("source_url"),
            "content_hash": row.get("content_hash"),
            "first_seen": row.get("first_seen"),
            "collected_at": row.get("collected_at"),
            "access_mode": row.get("access_mode") or "unknown",
            "web_layer": row.get("web_layer") or "unknown",
        })
    requested = sorted(set(requested_modules))
    if "all" in requested:
        selected = safe_findings
    else:
        matching_source_ids = {
            str(source.get("id"))
            for source in sources
            if any(_source_matches_module(source, module) for module in requested)
        }
        selected = [row for row in safe_findings if row["source_id"] in matching_source_ids]
    severity_counts = {level: sum(1 for row in selected if row["severity"] == level) for level in ("critical", "high", "medium", "low")}
    return {
        "report_version": "1",
        "generated_at": datetime.now(UTC).isoformat(),
        "target": {"kind": target_kind, "canonical_value": canonical_target, "value_hash": identifier_hash(canonical_target), "watch_id": watch_id},
        "execution_mode": "persisted_evidence_lookup",
        "fresh_collection_performed": False,
        "source_limitations": ["This endpoint queries previously persisted evidence; it does not initiate a fresh source collection."],
        "requested_modules": requested,
        "findings": selected,
        "finding_count": len(selected),
        "risk_summary": {"severity_counts": severity_counts, "unique_sources": len({row["source_id"] for row in selected}), "identity_attribution": "not_assessed"},
        "identity_links": [],
        "integration_matrix": build_integration_matrix(sources, evidence_count=len(selected)),
        "tenant_isolation": {"enforced": True, "scope": "authenticated tenant and tenant-owned watchlist"},
        "status": "results_found" if selected else "no_persisted_matches",
        "interpretation": "No persisted matches is not proof that the target has no exposure. Identity is not inferred from weak identifiers.",
    }
