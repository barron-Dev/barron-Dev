from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from cyclothone.attribution.engine import ActorProfile, AttributionEvidence, compute_attribution
from cyclothone.storage.supabase_client import supabase


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _merge_unique(existing: list[str] | None, incoming: list[str] | None) -> list[str]:
    return sorted({str(v).strip() for v in [*(existing or []), *(incoming or [])] if str(v).strip()})


def _merge_profile(profile: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    merged = dict(profile)
    for key in ("aliases", "attack_techniques", "malware_hashes", "malware_families", "target_sectors", "target_regions", "emails", "pgp_fingerprints", "wallets", "activity_timestamps", "tools", "major_campaigns", "evolution_notes"):
        if key in evidence:
            merged[key] = _merge_unique(merged.get(key), evidence.get(key))
    infra = dict(merged.get("infrastructure") or {})
    for key, values in (evidence.get("infrastructure") or {}).items():
        infra[key] = _merge_unique(infra.get(key), values)
    merged["infrastructure"] = infra
    if evidence.get("behavioural_features"):
        history = list(merged.get("behavioural_history") or [])[-9:]
        history.append({"observed_at": datetime.now(UTC).isoformat(), "features": evidence["behavioural_features"]})
        merged["behavioural_history"] = history
        merged["behavioural_features"] = evidence["behavioural_features"]
    return merged


async def assess_activity_cluster(activity: dict[str, Any]) -> dict[str, Any]:
    """Persist an attribution assessment for a complete cross-source activity cluster.

    Call after collection assembles a cluster with evidence IDs and provenance.
    Authorization and tenant policy must be enforced by the caller.
    """
    cluster_id = str(activity.get("activity_cluster_id") or "").strip()
    if not cluster_id or len(cluster_id) > 256:
        raise ValueError("activity_cluster_id_required")
    evidence = AttributionEvidence.from_dict(activity)
    client = await supabase._ensure()
    response = await client.table("dw_actor_profiles").select("actor_id,primary_name,actor_type,aliases,attributed_to,attribution_confidence,profile,first_seen,last_activity,source_count,analyst_review_required,provisional,profile_version").limit(5000).execute()
    candidates: list[tuple[float, dict[str, Any], dict[str, Any]]] = []
    for row in (response.data or []):
        profile_data = dict(row.get("profile") or {})
        profile_data.update({k: row.get(k) for k in ("actor_id", "primary_name", "actor_type", "aliases", "attributed_to", "attribution_confidence", "first_seen", "last_activity", "analyst_review_required", "profile_version") if row.get(k) is not None})
        score = compute_attribution(evidence, ActorProfile.from_dict(profile_data))
        candidates.append((float(score["score"]), row, score))
    candidates.sort(key=lambda item: item[0], reverse=True)
    best = candidates[0] if candidates else None
    matched = best if best and best[2]["tier"] in {"CONFIRMED", "SUSPECTED", "POSSIBLE"} else None
    now = datetime.now(UTC).isoformat()

    if matched:
        _, row, assessment = matched
        actor_id = str(row["actor_id"])
        profile_json = _merge_profile(dict(row.get("profile") or {}), activity) if assessment["tier"] in {"CONFIRMED", "SUSPECTED"} else dict(row.get("profile") or {})
        update = {
            "profile": profile_json, "last_activity": now,
            "source_count": int(row.get("source_count") or 0) + len(set(activity.get("independent_sources") or [])),
            "analyst_review_required": True,
            "profile_version": int(row.get("profile_version") or 1) + 1, "updated_at": now,
        }
        if assessment["tier"] in {"CONFIRMED", "SUSPECTED"}:
            update["aliases"] = _merge_unique(row.get("aliases"), activity.get("aliases"))
        await client.table("dw_actor_profiles").update(update).eq("actor_id", actor_id).execute()
    else:
        actor_id = "cluster-" + _canonical_hash({"cluster": cluster_id, "evidence": sorted(activity.get("source_evidence_ids") or [])})[:32]
        actor_name = str(activity.get("provisional_name") or f"Unattributed activity cluster {actor_id[-8:]}")[:200]
        profile_json = {
            "diamond_model": activity.get("diamond_model") or {},
            "attack_techniques": sorted(set(activity.get("attack_techniques") or [])),
            "infrastructure": activity.get("infrastructure") or {},
            "malware_families": sorted(set(activity.get("malware_families") or [])),
            "target_sectors": sorted(set(activity.get("target_sectors") or [])),
            "target_regions": sorted(set(activity.get("target_regions") or [])),
            "behavioural_features": activity.get("behavioural_features") or {},
            "source_evidence_ids": sorted(set(activity.get("source_evidence_ids") or [])),
            "provisional_reason": "No existing profile passed the POSSIBLE association threshold; not a real-world identity claim.",
        }
        await client.table("dw_actor_profiles").upsert({
            "actor_id": actor_id, "primary_name": actor_name, "actor_type": "UNKNOWN",
            "aliases": sorted(set(activity.get("aliases") or [])), "attribution_confidence": "INSUFFICIENT",
            "profile": profile_json, "first_seen": now, "last_activity": now,
            "source_count": len(set(activity.get("independent_sources") or [])),
            "analyst_review_required": True, "provisional": True, "profile_version": 1,
            "updated_at": now,
        }, on_conflict="actor_id").execute()
        assessment = compute_attribution(evidence, ActorProfile(actor_id=actor_id, primary_name=actor_name))
        assessment["tier"] = "INSUFFICIENT"
        assessment["reporting_language"] = "Cyclothone DW has insufficient evidence to associate this cluster with a known actor; provisional cluster created for analyst review."

    assessment_row = {
        "activity_cluster_id": cluster_id, "actor_id": actor_id,
        "score": assessment["score"], "tier": assessment["tier"],
        "raw_score_tier": assessment.get("raw_score_tier", assessment["tier"]),
        "signals": assessment["signals"], "explanation": assessment["explanation"],
        "diamond_model": activity.get("diamond_model") or {},
        "attack_techniques": activity.get("attack_techniques") or [],
        "kill_chain_phases": activity.get("kill_chain_phases") or [],
        "source_evidence_ids": activity.get("source_evidence_ids") or [],
        "independent_source_count": len(set(activity.get("independent_sources") or [])),
        "analyst_review_required": True,
    }
    saved = await client.table("dw_attribution_assessments").insert(assessment_row).execute()
    return {"actor_id": actor_id, "tier": assessment["tier"], "score": assessment["score"], "analyst_review_required": True, "assessment_id": (saved.data or [{}])[0].get("assessment_id")}
