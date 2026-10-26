from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx

from cyclothone.storage.supabase_client import supabase

logger = logging.getLogger(__name__)

DIRECTORY_URL = "https://securedrop.org/api/v1/directory/"
DIRECTORY_HOST = "securedrop.org"
MAX_BODY_BYTES = 4_000_000
MAX_ENTRIES = 5_000
ONION_V3_HOST = re.compile(r"^[a-z2-7]{56}\.onion$", re.IGNORECASE)


def _valid_https_url(value: object, allowed_hosts: set[str]) -> str | None:
    if not isinstance(value, str) or len(value) > 2048:
        return None
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme != "https" or host not in allowed_hosts:
            return None
        if parsed.username or parsed.password or parsed.port not in (None, 443):
            return None
        if parsed.query or parsed.fragment:
            return None
        return value
    except ValueError:
        return None


def parse_directory(body: bytes) -> list[dict]:
    """Validate official directory JSON into untrusted, candidate-only onion records."""
    if not body or len(body) > MAX_BODY_BYTES:
        raise ValueError("securedrop_directory_body_size_invalid")
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("securedrop_directory_invalid_json") from exc
    if not isinstance(payload, list) or len(payload) > MAX_ENTRIES:
        raise ValueError("securedrop_directory_shape_invalid")

    records: list[dict] = []
    seen: set[str] = set()
    for item in payload:
        if not isinstance(item, dict):
            continue
        raw_host = item.get("onion_address")
        if not isinstance(raw_host, str):
            continue
        host = raw_host.strip().lower().rstrip(".")
        if not ONION_V3_HOST.fullmatch(host) or host in seen:
            continue
        title = item.get("title")
        slug = item.get("slug")
        if not isinstance(title, str) or not title.strip() or not isinstance(slug, str) or not re.fullmatch(r"[a-z0-9-]{1,100}", slug):
            continue
        directory_url = _valid_https_url(item.get("directory_url"), {DIRECTORY_HOST, "www.securedrop.org"})
        if not directory_url:
            continue
        landing_url = _valid_https_url(item.get("landing_page_url"), {"securedrop.org", "www.securedrop.org"})
        organization_url = _valid_https_url(item.get("organization_url"), {"securedrop.org", "www.securedrop.org"})
        countries = item.get("countries")
        safe_countries = [v[:80] for v in countries[:20] if isinstance(v, str)] if isinstance(countries, list) else []
        languages = item.get("languages")
        safe_languages = [v[:40] for v in languages[:20] if isinstance(v, str)] if isinstance(languages, list) else []
        records.append({
            "url": f"https://{host}/",
            "hostname": host,
            "seed_origin": "discovered",
            "discovered_from": DIRECTORY_URL,
            "status": "candidate",
            "category_slug": "unclassified",
            "source_role": "securedrop_directory_candidate",
            "provenance_url": directory_url,
            "candidate_trust": "candidate",
            "monitoring_enabled": False,
            "seed_type": "publisher_onion",
            "requires_tor_probe": True,
            "quarantine_reason": "SecureDrop directory entry; candidate only until Tor reachability and publisher provenance are independently verified.",
            "country_scope": safe_countries[0] if len(safe_countries) == 1 else "GLOBAL",
            "coverage_notes": "Directory listing is not live onion reachability or independent publisher verification.",
            "probe_metadata": {
                "directory": "securedrop.org",
                "title": title.strip()[:200],
                "slug": slug,
                "landing_page_url": landing_url,
                "organization_url": organization_url,
                "countries": safe_countries,
                "languages": safe_languages,
                "directory_entry_url": directory_url,
                "directory_entry_validated": True,
                "tor_reachability_verified": False,
                "publisher_identity_verified": False,
                "customer_matching_allowed": False,
            },
        })
        seen.add(host)
    return records


class SecureDropDirectoryCollector:
    """Fetch the official HTTPS directory and persist candidates, never findings."""

    REGISTRY_KEY = "securedrop-official-directory-v1"

    async def run(self) -> dict:
        client = await supabase._ensure()
        registry_result = await (
            client.table("dw_source_discovery_registry")
            .select("enabled")
            .eq("registry_key", self.REGISTRY_KEY)
            .limit(1)
            .execute()
        )
        registry_rows = registry_result.data or []
        if not registry_rows or registry_rows[0].get("enabled") is not True:
            return {"state": "disabled", "candidate_count": 0, "customer_findings_created": 0}

        started = datetime.now(UTC).isoformat()
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(20.0, connect=8.0),
                follow_redirects=False,
                headers={"user-agent": "Cyclothone-SecureDrop-Directory/1.0", "accept": "application/json"},
            ) as http:
                async with http.stream("GET", DIRECTORY_URL) as response:
                    status = response.status_code
                    content_type = response.headers.get("content-type", "").lower()
                    if status != 200 or "json" not in content_type:
                        raise RuntimeError(f"securedrop_directory_http_{status}_or_non_json")
                    chunks: list[bytes] = []
                    size = 0
                    async for chunk in response.aiter_bytes():
                        remaining = MAX_BODY_BYTES - size
                        if remaining <= 0 or len(chunk) > remaining:
                            raise RuntimeError("securedrop_directory_body_too_large")
                        chunks.append(chunk)
                        size += len(chunk)
                    body = b"".join(chunks)
            digest = hashlib.sha256(body).hexdigest()
            candidates = parse_directory(body)
            hosts = [row["hostname"] for row in candidates]
            existing: set[str] = set()
            for offset in range(0, len(hosts), 200):
                batch = hosts[offset:offset + 200]
                rows = await (
                    client.table("dw_onion_seeds")
                    .select("hostname")
                    .in_("hostname", batch)
                    .execute()
                )
                existing.update(str(row["hostname"]).lower() for row in (rows.data or []) if row.get("hostname"))
            new_rows = [row for row in candidates if row["hostname"] not in existing]
            for offset in range(0, len(new_rows), 100):
                await client.table("dw_onion_seeds").insert(new_rows[offset:offset + 100]).execute()
            await client.table("dw_source_discovery_registry").update({
                "last_fetched_at": started,
                "last_http_status": status,
                "last_response_sha256": digest,
                "last_error": None,
                "metadata": {
                    "last_outcome": "directory_fetched_candidates_only",
                    "entry_count": len(candidates),
                    "new_candidate_count": len(new_rows),
                    "existing_candidate_count": len(candidates) - len(new_rows),
                    "customer_findings_created": 0,
                    "tor_reachability_verified": False,
                    "publisher_identity_verified": False,
                    "response_bytes": len(body),
                    "response_sha256": digest,
                },
                "updated_at": started,
            }).eq("registry_key", self.REGISTRY_KEY).execute()
            return {
                "state": "fetched_candidates_only",
                "http_status": status,
                "response_bytes": len(body),
                "response_sha256": digest,
                "candidate_count": len(candidates),
                "new_candidate_count": len(new_rows),
                "customer_findings_created": 0,
                "tor_reachability_verified": False,
            }
        except Exception as exc:
            await client.table("dw_source_discovery_registry").update({
                "last_fetched_at": started,
                "last_error": type(exc).__name__,
                "metadata": {"last_outcome": "fetch_failed", "error_type": type(exc).__name__, "customer_findings_created": 0},
                "updated_at": started,
            }).eq("registry_key", self.REGISTRY_KEY).execute()
            raise
