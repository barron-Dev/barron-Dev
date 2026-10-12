"""Canonical, honest source inventory for Cyclothone Dark Web coverage.

Catalog entries describe intended provider integrations, not proof of live access.
A provider is only "checked" when the request worker records a successful runtime
check. Catalog entries not included in the active request remain "not_run".
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable

# Keep this registry code-only until the production source-registry migration,
# RLS policies, and collector authorization have been reviewed and approved.
# access_mode distinguishes public feeds from credentials/explicit authorization.
SOURCE_CATALOG: tuple[dict[str, str], ...] = (
    {"source": "telegram_public", "category": "Messaging & social", "access_mode": "public_web_preview", "integration": "implemented"},
    {"source": "reddit_public", "category": "Messaging & social", "access_mode": "api_credentials", "integration": "planned"},
    {"source": "bluesky_public", "category": "Messaging & social", "access_mode": "public_api", "integration": "planned"},
    {"source": "tiktok_commercial", "category": "Messaging & social", "access_mode": "commercial_api_credentials", "integration": "planned"},
    {"source": "youtube_public", "category": "Messaging & social", "access_mode": "public_api", "integration": "planned"},
    {"source": "discord_public", "category": "Messaging & social", "access_mode": "authorized_api_or_public_content", "integration": "planned"},
    {"source": "ransomwatch", "category": "Ransomware & extortion", "access_mode": "public_archived_feed", "integration": "historical_only"},
    {"source": "ransomware_live", "category": "Ransomware & extortion", "access_mode": "public_feed_if_available", "integration": "planned"},
    {"source": "darknet_ransom_sites", "category": "Ransomware & extortion", "access_mode": "tor_access_and_policy_review", "integration": "planned"},
    {"source": "pastebin_public", "category": "Code, paste & exposed data", "access_mode": "public_feed", "integration": "implemented"},
    {"source": "github_code", "category": "Code, paste & exposed data", "access_mode": "api_credentials", "integration": "implemented"},
    {"source": "gitlab_code", "category": "Code, paste & exposed data", "access_mode": "public_api_or_credentials", "integration": "planned"},
    {"source": "public_package_registries", "category": "Code, paste & exposed data", "access_mode": "public_api", "integration": "planned"},
    {"source": "hibp", "category": "Identity & breach intelligence", "access_mode": "licensed_api_key_and_scope", "integration": "implemented"},
    {"source": "credential_dump_sources", "category": "Identity & breach intelligence", "access_mode": "restricted_data_policy_review", "integration": "excluded_until_approved"},
    {"source": "certificate_transparency", "category": "Identity & infrastructure", "access_mode": "public_feed", "integration": "planned"},
    {"source": "passive_dns", "category": "Identity & infrastructure", "access_mode": "provider_credentials_or_public_dataset", "integration": "planned"},
    {"source": "rdap_whois", "category": "Identity & infrastructure", "access_mode": "public_protocol_rate_limits", "integration": "planned"},
    {"source": "url_reputation", "category": "Identity & infrastructure", "access_mode": "provider_api_credentials", "integration": "planned"},
    {"source": "hackernews_public", "category": "Forums & public communities", "access_mode": "public_api", "integration": "planned"},
    {"source": "lemmy_public", "category": "Forums & public communities", "access_mode": "public_instance_api", "integration": "planned"},
    {"source": "authorized_security_forums", "category": "Forums & public communities", "access_mode": "explicit_authorization_required", "integration": "planned"},
    {"source": "public_web_search", "category": "Forums & public communities", "access_mode": "licensed_search_api_or_public_site", "integration": "planned"},
    {"source": "tor_public_sites", "category": "Tor & privacy networks", "access_mode": "tor_network_and_policy_review", "integration": "planned"},
    {"source": "i2p_public_sites", "category": "Tor & privacy networks", "access_mode": "i2p_network_and_policy_review", "integration": "planned"},
    {"source": "irc_public_channels", "category": "Real-time communities", "access_mode": "public_channel_policy_and_rate_limits", "integration": "planned"},
    {"source": "public_honeypot_feeds", "category": "Threat telemetry", "access_mode": "public_feed_or_owned_sensor", "integration": "planned"},
    {"source": "malware_hash_feeds", "category": "Threat telemetry", "access_mode": "public_feed_or_provider_credentials", "integration": "planned"},
    {"source": "threat_actor_advisories", "category": "Threat telemetry", "access_mode": "public_feed", "integration": "planned"},
)

def inventory_for_run(live_sources: Iterable[dict] = ()) -> dict:
    """Join observed request outcomes to the canonical catalog without guessing."""
    observed = {str(row.get("source")): dict(row) for row in live_sources if row.get("source")}
    categories: dict[str, list[dict]] = defaultdict(list)
    for entry in SOURCE_CATALOG:
        source_id = entry["source"]
        live = observed.get(source_id)
        if live is not None:
            state = str(live.get("state") or "unknown")
            reason = live.get("reason")
        elif entry["integration"] == "historical_only":
            state, reason = "historical_only", "not_a_live_source_check"
        elif entry["integration"] == "excluded_until_approved":
            state, reason = "excluded", "policy_review_required"
        elif entry["integration"] == "planned":
            state, reason = "not_implemented", "collector_not_wired"
        else:
            state, reason = "not_run", "not_in_this_request"
        categories[entry["category"]].append({
            **entry,
            "state": state,
            "reason": reason,
            "checked_at": live.get("checked_at") if live else None,
            "coverage": live.get("coverage") if live else None,
        })
    category_rows = []
    for name in sorted(categories):
        entries = categories[name]
        category_rows.append({
            "category": name,
            "sources_total": len(entries),
            "sources_checked": sum(item["state"] == "checked" for item in entries),
            "sources_failed": sum(item["state"] == "failed" for item in entries),
            "sources_unavailable": sum(item["state"] in {"unavailable", "not_implemented", "historical_only", "excluded"} for item in entries),
            "sources_not_run": sum(item["state"] in {"not_run", "unknown"} for item in entries),
            "sources": entries,
        })
    return {
        "catalog_version": 1,
        "catalog_scope": "known integrations and planned categories; not a claim of complete internet or dark-web coverage",
        "source_count": len(SOURCE_CATALOG),
        "category_count": len(category_rows),
        "categories": category_rows,
    }
