from __future__ import annotations

import asyncio
import json
import logging
import os
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)
DEFAULT_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
MAX_BYTES = 70 * 1024 * 1024


def _download_catalogue(url: str) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": "Cyclothone-DW-ATTACK-Catalogue/1.0", "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=25) as response:
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("attack_catalogue_exceeds_size_limit")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict) or not isinstance(parsed.get("objects"), list):
        raise ValueError("invalid_attack_stix_bundle")
    return parsed


def _extract_techniques(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    output = []
    for item in bundle.get("objects", []):
        if not isinstance(item, dict) or item.get("type") != "attack-pattern" or item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        refs = item.get("external_references") or []
        attack_ref = next((ref for ref in refs if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack" and str(ref.get("external_id") or "").startswith("T")), None)
        if not attack_ref:
            continue
        technique_id = str(attack_ref["external_id"]).upper()
        phases = sorted({str(p.get("phase_name")) for p in (item.get("kill_chain_phases") or []) if isinstance(p, dict) and p.get("kill_chain_name") == "mitre-attack" and p.get("phase_name")})
        output.append({
            "technique_id": technique_id, "name": str(item.get("name") or technique_id)[:300],
            "description": str(item.get("description") or "")[:8000],
            "platforms": sorted({str(p)[:100] for p in (item.get("x_mitre_platforms") or [])}),
            "tactics": phases, "url": next((str(r.get("url")) for r in refs if isinstance(r, dict) and r.get("source_name") == "mitre-attack" and r.get("url")), None),
            "stix_id": str(item.get("id") or "")[:100],
        })
    if not output:
        raise ValueError("attack_catalogue_contains_no_techniques")
    return output


def _extract_actor_profiles(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    objects = [item for item in bundle.get("objects", []) if isinstance(item, dict)]
    techniques_by_stix: dict[str, str] = {}
    groups = []
    targets_by_group: dict[str, list[dict[str, Any]]] = {}
    by_id = {str(item.get("id")): item for item in objects if item.get("id")}
    for item in objects:
        if item.get("type") == "attack-pattern" and not item.get("revoked") and not item.get("x_mitre_deprecated"):
            ref = next((r for r in (item.get("external_references") or []) if isinstance(r, dict) and r.get("source_name") == "mitre-attack" and str(r.get("external_id") or "").startswith("T")), None)
            if ref:
                techniques_by_stix[str(item["id"])] = str(ref["external_id"]).upper()
        if item.get("type") == "intrusion-set" and not item.get("revoked") and not item.get("x_mitre_deprecated"):
            ref = next((r for r in (item.get("external_references") or []) if isinstance(r, dict) and r.get("source_name") == "mitre-attack" and str(r.get("external_id") or "").startswith("G")), None)
            if ref:
                groups.append((item, str(ref["external_id"]).upper()))
    for rel in objects:
        if rel.get("type") == "relationship" and rel.get("relationship_type") == "uses" and rel.get("source_ref"):
            targets_by_group.setdefault(str(rel["source_ref"]), []).append(by_id.get(str(rel.get("target_ref")), {}))
    output = []
    for group, external_id in groups:
        aliases = sorted({str(x).strip()[:200] for x in (group.get("x_mitre_aliases") or []) if str(x).strip()})
        related = targets_by_group.get(str(group.get("id")), [])
        techniques = sorted({techniques_by_stix[str(target.get("id"))] for target in related if str(target.get("id")) in techniques_by_stix})
        tools = sorted({str(target.get("name"))[:200] for target in related if target.get("type") == "tool" and target.get("name")})
        malware = sorted({str(target.get("name"))[:200] for target in related if target.get("type") == "malware" and target.get("name")})
        refs = group.get("external_references") or []
        url = next((str(ref.get("url")) for ref in refs if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack" and ref.get("url")), None)
        output.append({
            "actor_id": "mitre-attack-" + external_id,
            "primary_name": str(group.get("name") or external_id)[:200],
            "aliases": aliases,
            "profile": {
                "source": "MITRE ATT&CK Enterprise STIX",
                "source_url": url,
                "description": str(group.get("description") or "")[:8000],
                "attack_techniques": techniques,
                "tools": tools,
                "malware_families": malware,
                "known_aliases": aliases,
            },
            "first_seen": group.get("created"),
            "last_activity": group.get("modified"),
        })
    return output


async def _upsert_actor_reference_profiles(client, bundle: dict[str, Any]) -> int:
    profiles = _extract_actor_profiles(bundle)
    if not profiles:
        return 0
    ids = [p["actor_id"] for p in profiles]
    response = await client.table("dw_actor_profiles").select(
        "actor_id,profile,aliases,first_seen,last_activity,profile_version,review_status,source_count"
    ).in_("actor_id", ids).is_("tenant_id", "null").execute()
    existing = {str(row["actor_id"]): row for row in (response.data or [])}
    for item in profiles:
        prior = existing.get(item["actor_id"]) or {}
        profile = dict(prior.get("profile") or {})
        profile.update(item["profile"])
        aliases = sorted(set([*(prior.get("aliases") or []), *item["aliases"]]))
        prior_first, new_first = prior.get("first_seen"), item.get("first_seen")
        first_seen = min([v for v in (prior_first, new_first) if v]) if prior_first or new_first else None
        prior_last, new_last = prior.get("last_activity"), item.get("last_activity")
        last_activity = max([v for v in (prior_last, new_last) if v]) if prior_last or new_last else None
        await client.table("dw_actor_profiles").upsert({
            "actor_id": item["actor_id"], "tenant_id": None,
            "primary_name": item["primary_name"], "actor_type": "UNKNOWN",
            "aliases": aliases, "attribution_confidence": "INSUFFICIENT",
            "profile": profile, "first_seen": first_seen, "last_activity": last_activity,
            "source_count": max(1, int(prior.get("source_count") or 1)),
            "analyst_review_required": False, "provisional": False,
            "profile_version": int(prior.get("profile_version") or 0) + 1,
            "review_status": prior.get("review_status") or "accepted",
            "updated_at": datetime.now(UTC).isoformat(),
        }, on_conflict="actor_id").execute()
    return len(profiles)


async def sync_attack_catalogue(force: bool = False) -> dict[str, Any]:
    if os.getenv("CYCLOTHONE_ATTACK_CATALOG_SYNC_ENABLED", "false").strip().lower() not in {"1", "true", "yes"}:
        return {"status": "disabled", "reason": "set CYCLOTHONE_ATTACK_CATALOG_SYNC_ENABLED=true to enable the official public MITRE STIX sync"}
    client = None
    try:
        from cyclothone.storage.supabase_client import supabase
        client = await supabase._ensure()
        if not force:
            state = await client.table("dw_attack_catalogue_state").select("last_success_at,technique_count").eq("catalogue_id", "enterprise-attack").limit(1).execute()
            row = (state.data or [{}])[0]
            if row.get("last_success_at"):
                last = datetime.fromisoformat(str(row["last_success_at"]).replace("Z", "+00:00"))
                if datetime.now(UTC) - last < timedelta(hours=24):
                    return {"status": "fresh", "technique_count": row.get("technique_count"), "last_success_at": row["last_success_at"]}
        url = (os.getenv("CYCLOTHONE_ATTACK_STIX_URL") or DEFAULT_URL).strip()
        bundle = await asyncio.to_thread(_download_catalogue, url)
        techniques = _extract_techniques(bundle)
        for start in range(0, len(techniques), 250):
            await client.table("dw_attack_techniques").upsert(
                techniques[start:start + 250], on_conflict="technique_id"
            ).execute()
        actor_profile_count = await _upsert_actor_reference_profiles(client, bundle)
        await client.table("dw_attack_catalogue_state").upsert({
            "catalogue_id": "enterprise-attack", "source_url": url,
            "last_success_at": datetime.now(UTC).isoformat(), "technique_count": len(techniques),
            "last_error_code": None,
        }, on_conflict="catalogue_id").execute()
        return {"status": "synced", "technique_count": len(techniques), "actor_profile_count": actor_profile_count, "source_url": url}
    except Exception as exc:
        logger.warning("MITRE ATT&CK catalogue sync failed error=%s", type(exc).__name__)
        if client is not None:
            try:
                await client.table("dw_attack_catalogue_state").upsert({
                    "catalogue_id": "enterprise-attack",
                    "last_error_code": type(exc).__name__[:80],
                }, on_conflict="catalogue_id").execute()
            except Exception:
                pass
        return {"status": "failed", "error_code": type(exc).__name__}
