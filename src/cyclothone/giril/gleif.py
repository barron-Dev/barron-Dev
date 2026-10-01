from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.request import Request, urlopen

GLEIF_PUBLISHES_URL = "https://goldencopy.gleif.org/api/v2/golden-copies/publishes/lei2/latest"


@dataclass(frozen=True)
class GleifPublication:
    version: str
    cdf_version: str
    file_urls: tuple[str, ...]


def fetch_latest_publication(timeout: int = 30) -> GleifPublication:
    req = Request(GLEIF_PUBLISHES_URL, headers={"Accept": "application/json", "User-Agent": "Cyclothone-GIRIL/1.0"})
    with urlopen(req, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("GLEIF publication response is not an object")
    data = payload.get("data", payload)
    if not isinstance(data, (dict, list)):
        raise ValueError("GLEIF publication response has no usable data")
    candidates = data if isinstance(data, list) else [data]
    urls: list[str] = []
    versions: list[str] = []
    cdf_versions: list[str] = []
    for item in candidates:
        if not isinstance(item, dict):
            continue
        attrs = item.get("attributes", item)
        if not isinstance(attrs, dict):
            continue
        for key in ("file_url", "download_url", "url"):
            value = attrs.get(key)
            if isinstance(value, str) and value.startswith("https://"):
                urls.append(value)
        for key in ("publish_date", "publication_date", "version", "name"):
            value = attrs.get(key)
            if value is not None:
                versions.append(str(value))
        value = attrs.get("cdf_version")
        if value is not None:
            cdf_versions.append(str(value))
    if not urls:
        raise ValueError("GLEIF latest publication contained no HTTPS download URL")
    return GleifPublication(
        version=versions[0] if versions else "unknown",
        cdf_version=cdf_versions[0] if cdf_versions else "unknown",
        file_urls=tuple(dict.fromkeys(urls)),
    )


def normalize_lei_record(record: dict[str, Any], source_version: str, manifest_hash: str, source_id: str) -> dict[str, Any]:
    """Map only stable Level-1 identity fields; ignore unknown GLEIF fields for forward compatibility."""
    lei = str(record.get("lei", "")).upper()
    if len(lei) != 20 or not lei.isalnum():
        raise ValueError("Invalid LEI identifier")
    entity = record.get("entity") or {}
    legal_name = ((entity.get("legalName") or {}).get("name") or "").strip()
    if not legal_name:
        raise ValueError("GLEIF record has no legal name")
    return {
        "lei": lei,
        "legal_name": legal_name,
        "entity_status": entity.get("status"),
        "jurisdiction_country_iso2": entity.get("legalAddress", {}).get("country"),
        "registration_authority_id": (entity.get("registeredAt") or {}).get("id"),
        "registration_authority_entity_id": (entity.get("registeredAt") or {}).get("other"),
        "legal_form_code": (entity.get("legalForm") or {}).get("id"),
        "legal_address": entity.get("legalAddress") or {},
        "headquarters_address": entity.get("headquartersAddress") or {},
        "initial_registration_date": entity.get("initialRegistrationDate"),
        "last_update_date": entity.get("lastUpdateDate"),
        "next_renewal_date": entity.get("nextRenewalDate"),
        "source_id": source_id,
        "source_version": source_version,
        "source_manifest_hash": manifest_hash,
    }
