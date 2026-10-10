from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from cyclothone.attribution.engine import ActorProfile, AttributionEvidence, compute_attribution
from cyclothone.storage.supabase_client import supabase


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _merge_unique(existing: list[str] | None, incoming: list[str] | None) -> list[str]:
    return sorted({str(v).strip() for v in [*(existing or []), *(incoming or [])] if str(v).strip()})


def _safe_source_url(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parts = urlsplit(value.strip())
        if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
            return None
        return urlunsplit((parts.scheme, parts.netloc, parts.path[:2048], "", ""))
    except ValueError:
        return None


def _merge_profile(profile: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    """Merge tenant-local intelligence only; never put customer identifiers in global CTI."""
    merged = dict(profile)
    for key in ("attack_techniques", "capec_ids", "malware_hashes", "malware_families", "target_sectors", "target_regions", "tools", "major_campaigns", "evolution_notes", "independent_sources", "source_evidence_ids"):
        if key in evidence:
            merged[key] = _merge_unique(merged.get(key), evidence.get(key))
    infra = dict(merged.get("infrastructure") or {})
    for key, values in (evidence.get("infrastructure") or {}).items():
        infra[key] = _merge_unique(infra.get(key), values)
    merged["infrastructure"] = infra
    if evidence.get("diamond_model"):
        diamond = dict(merged.get("diamond_model") or {})
        for vertex in ("adversary", "capability", "infrastructure", "victim"):
            old_vertex = dict(diamond.get(vertex) or {})
            new_vertex = dict((evidence.get("diamond_model") or {}).get(vertex) or {})
            for key, value in new_vertex.items():
                if isinstance(value, list):
                    old_vertex[key] = _merge_unique(old_vertex.get(key), value)
                elif value == "observed" or key not in old_vertex:
                    old_vertex[key] = value
            diamond[vertex] = old_vertex
        merged["diamond_model"] = diamond
    if evidence.get("behavioural_features"):
        history = list(merged.get("behavioural_history") or [])[-9:]
        history.append({"observed_at": datetime.now(UTC).isoformat(), "features": evidence["behavioural_features"]})
        merged["behavioural_history"] = history
        merged["behavioural_features"] = evidence["behavioural_features"]
    return merged


async def assess_activity_cluster(activity: dict[str, Any]) -> dict[str, Any]:
    """Persist a tenant-scoped assessment, evidence, provisional profile and relationships."""
    cluster_id = str(activity.get("activity_cluster_id") or "").strip()
    tenant_id = str(activity.get("tenant_id") or "").strip()
    if not cluster_id or len(cluster_id) > 256 or not tenant_id:
        raise ValueError("activity_cluster_and_tenant_required")
    evidence = AttributionEvidence.from_dict(activity)
    client = await supabase._ensure()
    response = await client.table("dw_actor_profiles").select(
        "actor_id,tenant_id,primary_name,actor_type,aliases,attributed_to,attribution_confidence,profile,first_seen,last_activity,source_count,analyst_review_required,provisional,profile_version"
    ).limit(5000).execute()
    candidates: list[tuple[float, dict[str, Any], dict[str, Any]]] = []
    for row in (response.data or []):
        if row.get("tenant_id") not in (None, tenant_id):
            continue
        profile_data = dict(row.get("profile") or {})
        profile_data.update({k: row.get(k) for k in ("actor_id", "primary_name", "actor_type", "aliases", "attributed_to", "attribution_confidence", "first_seen", "last_activity", "analyst_review_required", "profile_version") if row.get(k) is not None})
        score = compute_attribution(evidence, ActorProfile.from_dict(profile_data))
        candidates.append((float(score["score"]), row, score))
    candidates.sort(key=lambda item: item[0], reverse=True)
    best = candidates[0] if candidates else None
    matched = best if best and best[2]["tier"] in {"CONFIRMED", "SUSPECTED", "POSSIBLE"} else None
    now = datetime.now(UTC).isoformat()
    provisional_created = False
    event_type = "ATTRIBUTION_TIER_CHANGED"

    if matched:
        _, row, assessment = matched
        actor_id = str(row["actor_id"])
        if row.get("tenant_id") == tenant_id and assessment["tier"] in {"CONFIRMED", "SUSPECTED", "POSSIBLE"}:
            event_type = "PROFILE_CHANGED"
            profile_json = _merge_profile(dict(row.get("profile") or {}), activity)
            await client.table("dw_actor_profiles").update({
                "profile": profile_json, "last_activity": now,
                "source_count": len(set(_merge_unique((row.get("profile") or {}).get("independent_sources"), activity.get("independent_sources")))),
                "aliases": _merge_unique(row.get("aliases"), activity.get("aliases")),
                "attribution_confidence": assessment["tier"],
                "analyst_review_required": True, "profile_version": int(row.get("profile_version") or 1) + 1,
                "updated_at": now,
            }).eq("actor_id", actor_id).eq("tenant_id", tenant_id).execute()
    else:
        # Stable by tenant+cluster, not by the changing evidence list: new observations
        # enrich the same provisional cluster instead of creating duplicate actors.
        actor_id = "cluster-" + _canonical_hash({"tenant": tenant_id, "cluster": cluster_id})[:32]
        actor_name = str(activity.get("provisional_name") or f"Unattributed activity cluster {actor_id[-8:]}")[:200]
        existing_result = await client.table("dw_actor_profiles").select(
            "profile,aliases,first_seen,source_count,profile_version"
        ).eq("actor_id", actor_id).eq("tenant_id", tenant_id).limit(1).execute()
        existing = (existing_result.data or [{}])[0]
        base_profile = {
            "diamond_model": activity.get("diamond_model") or {},
            "attack_techniques": sorted(set(activity.get("attack_techniques") or [])),
            "capec_ids": sorted(set(activity.get("capec_ids") or [])),
            "infrastructure": activity.get("infrastructure") or {},
            "malware_families": sorted(set(activity.get("malware_families") or [])),
            "target_sectors": sorted(set(activity.get("target_sectors") or [])),
            "target_regions": sorted(set(activity.get("target_regions") or [])),
            "behavioural_features": activity.get("behavioural_features") or {},
            "source_evidence_ids": sorted(set(activity.get("source_evidence_ids") or [])),
            "independent_sources": sorted(set(activity.get("independent_sources") or [])),
            "provisional_reason": "No existing profile passed the POSSIBLE association threshold; this is not a real-world identity claim.",
        }
        profile_json = _merge_profile(dict(existing.get("profile") or {}), activity) if existing.get("profile") else base_profile
        profile_json["source_evidence_ids"] = _merge_unique(profile_json.get("source_evidence_ids"), activity.get("source_evidence_ids"))
        profile_json["independent_sources"] = _merge_unique(profile_json.get("independent_sources"), activity.get("independent_sources"))
        old_diamond = dict(profile_json.get("diamond_model") or {})
        new_diamond = activity.get("diamond_model") or {}
        for vertex in ("adversary", "capability", "infrastructure", "victim"):
            old_vertex = dict(old_diamond.get(vertex) or {})
            new_vertex = dict(new_diamond.get(vertex) or {})
            for key, value in new_vertex.items():
                if isinstance(value, list):
                    old_vertex[key] = _merge_unique(old_vertex.get(key), value)
                elif value == "observed" or key not in old_vertex:
                    old_vertex[key] = value
            old_diamond[vertex] = old_vertex
        profile_json["diamond_model"] = old_diamond
        await client.table("dw_actor_profiles").upsert({
            "actor_id": actor_id, "tenant_id": tenant_id, "primary_name": actor_name, "actor_type": "UNKNOWN",
            "aliases": _merge_unique(existing.get("aliases"), activity.get("aliases")),
            "attribution_confidence": "INSUFFICIENT", "profile": profile_json,
            "first_seen": existing.get("first_seen") or now, "last_activity": now,
            "source_count": len(set(profile_json.get("independent_sources") or [])),
            "analyst_review_required": True, "provisional": True,
            "profile_version": int(existing.get("profile_version") or 0) + 1,
            "review_status": "pending", "updated_at": now,
        }, on_conflict="actor_id").execute()
        assessment = compute_attribution(evidence, ActorProfile(actor_id=actor_id, primary_name=actor_name))
        assessment["tier"] = "INSUFFICIENT"
        assessment["reporting_language"] = "Cyclothone DW has insufficient evidence to associate this cluster with a known actor; provisional cluster created for analyst review."
        provisional_created = not bool(existing.get("first_seen"))
        event_type = "PROVISIONAL_ACTOR_CREATED" if provisional_created else "PROFILE_CHANGED"

    for record in (activity.get("evidence_records") or []):
        if not isinstance(record, dict):
            continue
        evidence_type = str(record.get("evidence_type") or "SOURCE_REPORT").upper()
        if evidence_type not in {"INFRASTRUCTURE", "TTP", "MALWARE", "BEHAVIOUR", "VICTIMOLOGY", "IDENTITY", "TEMPORAL", "SOURCE_REPORT"}:
            evidence_type = "SOURCE_REPORT"
        source_name = str(record.get("source_name") or "unknown")[:120]
        metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
        safe_metadata = {k: metadata[k] for k in ("technique_ids", "indicator_types", "collection_method", "provider_record_id") if k in metadata and isinstance(metadata[k], (str, int, float, list))}
        evidence_hash = str(record.get("evidence_hash") or _canonical_hash({"cluster": cluster_id, "type": evidence_type, "source": source_name, "metadata": safe_metadata})).lower()
        if len(evidence_hash) != 64 or any(ch not in "0123456789abcdef" for ch in evidence_hash):
            evidence_hash = _canonical_hash({"cluster": cluster_id, "type": evidence_type, "hash": evidence_hash})
        try:
            confidence = max(0.0, min(1.0, float(record.get("confidence", 0.5))))
        except (TypeError, ValueError):
            confidence = 0.5
        await client.table("dw_actor_evidence").upsert({
            "tenant_id": tenant_id, "actor_id": actor_id, "activity_cluster_id": cluster_id,
            "evidence_type": evidence_type, "evidence_hash": evidence_hash,
            "source_name": source_name, "source_url": _safe_source_url(record.get("source_url")),
            "observed_at": record.get("observed_at") if isinstance(record.get("observed_at"), str) else None,
            "confidence": confidence, "metadata": safe_metadata,
        }, on_conflict="tenant_id,activity_cluster_id,evidence_hash,evidence_type").execute()

    # Candidate actor relationships are explainable and review-gated. No relationship
    # is created from behavioural or temporal similarity alone.
    relation_candidates = list(activity.get("relationship_candidates") or [])
    if len(set(activity.get("independent_sources") or [])) >= 2:
        for _, candidate_row, candidate_score in candidates:
            target_id = str(candidate_row.get("actor_id") or "")
            if not target_id or target_id == actor_id or candidate_score.get("tier") not in {"CONFIRMED", "SUSPECTED", "POSSIBLE"}:
                continue
            signals = candidate_score.get("signals") or {}
            if float(signals.get("infrastructure") or 0) > 0:
                relation_type = "SHARES_INFRASTRUCTURE_WITH"
            elif float(signals.get("ttp") or 0) > 0:
                relation_type = "SHARES_TTP_WITH"
            else:
                continue
            relation_candidates.append({"target_actor_id": target_id, "relationship_type": relation_type, "confidence": candidate_score["score"], "evidence_ids": activity.get("source_evidence_ids") or []})
    for relation in relation_candidates[:100]:
        if not isinstance(relation, dict):
            continue
        target_id = str(relation.get("target_actor_id") or "")
        relation_type = str(relation.get("relationship_type") or "POSSIBLE_ASSOCIATION").upper()
        if not target_id or target_id == actor_id or relation_type not in {"AFFILIATED_WITH", "SUSPECTED_SPLINTER_OF", "SHARES_INFRASTRUCTURE_WITH", "SHARES_TTP_WITH", "REBRANDED_AS", "POSSIBLE_ASSOCIATION"}:
            continue
        target = await client.table("dw_actor_profiles").select("actor_id,tenant_id").eq("actor_id", target_id).limit(1).execute()
        target_rows = target.data or []
        if not target_rows or target_rows[0].get("tenant_id") not in (None, tenant_id):
            continue
        try:
            confidence = max(0.0, min(1.0, float(relation.get("confidence", 0.0))))
        except (TypeError, ValueError):
            confidence = 0.0
        await client.table("dw_actor_relationships").upsert({
            "tenant_id": tenant_id, "source_actor_id": actor_id, "target_actor_id": target_id,
            "relationship_type": relation_type, "confidence": confidence,
            "evidence_ids": sorted(set(relation.get("evidence_ids") or [])),
            "analyst_review_required": True, "updated_at": now,
        }, on_conflict="source_actor_id,target_actor_id,relationship_type").execute()

    assessment_row = {
        "tenant_id": tenant_id, "activity_cluster_id": cluster_id, "actor_id": actor_id,
        "score": assessment["score"], "tier": assessment["tier"],
        "raw_score_tier": assessment.get("raw_score_tier", assessment["tier"]),
        "signals": assessment["signals"], "explanation": assessment["explanation"],
        "diamond_model": activity.get("diamond_model") or {},
        "attack_techniques": activity.get("attack_techniques") or [],
        "kill_chain_phases": activity.get("kill_chain_phases") or [],
        "unified_kill_chain_phases": activity.get("unified_kill_chain_phases") or [],
        "capec_ids": activity.get("capec_ids") or [],
        "source_evidence_ids": activity.get("source_evidence_ids") or [],
        "independent_source_count": len(set(activity.get("independent_sources") or [])),
        "analyst_review_required": True, "review_status": "pending",
    }
    saved = await client.table("dw_attribution_assessments").upsert(
        assessment_row, on_conflict="tenant_id,activity_cluster_id"
    ).select("assessment_id").execute()
    assessment_id = (saved.data or [{}])[0].get("assessment_id")
    if assessment_id:
        event_fingerprint = _canonical_hash({"cluster": cluster_id, "actor": actor_id, "event_type": event_type, "score": assessment["score"], "tier": assessment["tier"], "evidence": sorted(activity.get("source_evidence_ids") or [])})
        alert_payload = {
            "event_type": event_type, "assessment_id": assessment_id, "actor_id": actor_id,
            "activity_cluster_id": cluster_id, "score": assessment["score"], "tier": assessment["tier"],
            "independent_source_count": len(set(activity.get("independent_sources") or [])),
            "analyst_review_required": True, "created_at": now,
        }
        await client.table("dw_attribution_alert_outbox").upsert({
            "tenant_id": tenant_id, "assessment_id": assessment_id,
            "event_type": event_type, "event_fingerprint": event_fingerprint, "payload": alert_payload,
        }, on_conflict="tenant_id,assessment_id,event_type,event_fingerprint").execute()
    return {"actor_id": actor_id, "tier": assessment["tier"], "score": assessment["score"], "analyst_review_required": True, "assessment_id": assessment_id, "provisional_created": provisional_created}
