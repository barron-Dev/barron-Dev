from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any

from cyclothone.attribution.engine import build_diamond_model, map_kill_chain_phase, validate_attack_techniques

_HASH = re.compile(r"^[a-f0-9]{64}$")
_ALLOWED_INFRA = {"domains", "ips", "hosting_providers", "tls_certificates", "c2_frameworks"}
_ALLOWED_EVIDENCE = {"INFRASTRUCTURE", "TTP", "MALWARE", "BEHAVIOUR", "VICTIMOLOGY", "IDENTITY", "TEMPORAL", "SOURCE_REPORT"}


def _list(values: Any, *, limit: int = 500) -> list[str]:
    if values is None or isinstance(values, (str, bytes, dict)):
        return []
    try:
        return sorted({str(v).strip()[:512] for v in values if str(v).strip()})[:limit]
    except TypeError:
        return []


def _hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def assemble_activity_cluster(records: list[dict[str, Any]], *, tenant_id: str, cluster_key: str | None = None) -> dict[str, Any]:
    """Normalize bounded, provenance-backed records into an attribution cluster."""
    if not tenant_id or len(tenant_id) > 128:
        raise ValueError("tenant_id_required")
    if not records or len(records) > 1000:
        raise ValueError("cluster_requires_1_to_1000_records")
    normalized = []
    for item in records:
        if not isinstance(item, dict):
            continue
        source = str(item.get("source_name") or item.get("source_id") or "").strip().lower()[:120]
        record_id = str(item.get("evidence_id") or item.get("record_id") or "").strip()[:256]
        if source and record_id:
            normalized.append((source, record_id, item))
    if not normalized:
        raise ValueError("cluster_requires_source_provenance")
    normalized.sort(key=lambda row: (row[0], row[1]))
    stable_key = cluster_key or _hash([[s, rid] for s, rid, _ in normalized])
    cluster_id = "ac-" + _hash({"tenant": tenant_id, "cluster": stable_key})[:40]

    infrastructure: dict[str, set[str]] = {k: set() for k in _ALLOWED_INFRA}
    techniques: set[str] = set()
    malware_hashes: set[str] = set()
    malware_families: set[str] = set()
    tools: set[str] = set()
    sectors: set[str] = set()
    regions: set[str] = set()
    aliases: set[str] = set()
    emails: set[str] = set()
    pgp: set[str] = set()
    wallets: set[str] = set()
    timestamps: set[str] = set()
    actions: set[str] = set()
    evidence_ids: set[str] = set()
    sources: set[str] = set()
    evidence_records = []
    adversary_handles: set[str] = set()
    known_associations: set[str] = set()
    org_sizes: set[str] = set()
    for source, record_id, item in normalized:
        evidence_ids.add(record_id)
        sources.add(source)
        infra = item.get("infrastructure") or {}
        if isinstance(infra, dict):
            for key in _ALLOWED_INFRA:
                infrastructure[key].update(v.lower() for v in _list(infra.get(key)))
        techniques.update(validate_attack_techniques(item.get("attack_techniques") or item.get("techniques")))
        malware_hashes.update(v.lower() for v in _list(item.get("malware_hashes")) if _HASH.fullmatch(v.lower()))
        malware_families.update(_list(item.get("malware_families")))
        tools.update(_list(item.get("tools")))
        sectors.update(_list(item.get("target_sectors") or item.get("sectors")))
        regions.update(_list(item.get("target_regions") or item.get("regions")))
        aliases.update(_list(item.get("aliases")))
        emails.update(_list(item.get("emails")))
        pgp.update(_list(item.get("pgp_fingerprints")))
        wallets.update(_list(item.get("wallets")))
        timestamp = item.get("observed_at") or item.get("collected_at")
        if timestamp:
            timestamps.add(str(timestamp)[:80])
        actions.update(_list(item.get("observed_actions")))
        adversary_handles.update(_list(item.get("actor_handles") or item.get("handles")))
        known_associations.update(_list(item.get("known_associations")))
        org_sizes.update(_list(item.get("organisation_sizes") or item.get("organization_sizes")))
        raw_hash = str(item.get("evidence_hash") or "")
        if not _HASH.fullmatch(raw_hash.lower()):
            raw_hash = _hash({"source": source, "record_id": record_id, "content": item.get("content_hash") or item.get("indicator_hash") or item.get("title") or ""})
        evidence_type = str(item.get("evidence_type") or "SOURCE_REPORT").upper()
        if evidence_type not in _ALLOWED_EVIDENCE:
            evidence_type = "SOURCE_REPORT"
        evidence_records.append({
            "evidence_type": evidence_type, "evidence_hash": raw_hash.lower(),
            "source_name": source, "source_url": item.get("source_url"),
            "observed_at": timestamp, "confidence": item.get("confidence", 0.5),
            "metadata": {"technique_ids": validate_attack_techniques(item.get("attack_techniques") or item.get("techniques")), "collection_method": str(item.get("collection_method") or "provider_record")[:80], "provider_record_id": record_id},
        })
    infra_json = {k: sorted(v) for k, v in infrastructure.items()}
    activity = {
        "activity_cluster_id": cluster_id, "tenant_id": tenant_id,
        "infrastructure": infra_json, "attack_techniques": sorted(techniques),
        "malware_hashes": sorted(malware_hashes), "malware_families": sorted(malware_families),
        "tools": sorted(tools), "target_sectors": sorted(sectors), "target_regions": sorted(regions),
        "aliases": sorted(aliases), "emails": sorted(emails), "pgp_fingerprints": sorted(pgp),
        "wallets": sorted(wallets), "activity_timestamps": sorted(timestamps),
        "observed_actions": sorted(actions), "source_evidence_ids": sorted(evidence_ids),
        "independent_sources": sorted(sources), "evidence_records": evidence_records,
        "diamond_model": build_diamond_model({
            "adversary": {"handles": adversary_handles, "aliases": aliases, "known_associations": known_associations},
            "capability": {"malware_hashes": malware_hashes, "malware_families": malware_families, "tools": tools, "attack_techniques": techniques},
            "infrastructure": infra_json,
            "victim": {"sectors": sectors, "regions": regions, "organisation_sizes": org_sizes},
        }),
        "kill_chain_phases": map_kill_chain_phase(actions), "assembled_at": datetime.now(UTC).isoformat(),
    }
    return activity
