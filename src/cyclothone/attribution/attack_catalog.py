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
        await client.table("dw_attack_catalogue_state").upsert({
            "catalogue_id": "enterprise-attack", "source_url": url,
            "last_success_at": datetime.now(UTC).isoformat(), "technique_count": len(techniques),
            "last_error_code": None,
        }, on_conflict="catalogue_id").execute()
        return {"status": "synced", "technique_count": len(techniques), "source_url": url}
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
