from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable
from uuid import UUID, NAMESPACE_URL, uuid5

STIX_VERSION = "2.1"
STIX_NS = UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
SUPPORTED_TYPES = {"sha256", "domain", "ipv4", "ipv6", "url", "email", "ja3", "btc_address", "mutex"}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _stix_id(kind: str, ioc_type: str, value_hash: str) -> str:
    return f"{kind}--{uuid5(STIX_NS, f'{ioc_type}:{value_hash}')}"


def _pattern_for(ioc_type: str, value: str) -> str:
    mapping = {
        "sha256": "file:hashes.'SHA-256'",
        "domain": "domain-name:value",
        "ipv4": "ipv4-addr:value",
        "ipv6": "ipv6-addr:value",
        "url": "url:value",
        "email": "email-addr:value",
        "ja3": "x-sentinel-ja3:value",
        "btc_address": "x-sentinel-btc-address:value",
        "mutex": "x-sentinel-mutex:value",
    }
    field = mapping.get(ioc_type)
    if not field:
        raise ValueError(f"unsupported IOC type: {ioc_type}")
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return f"[{field} = '{escaped}']"


def indicator_to_stix(indicator: dict[str, Any], *, source_name: str = "Sentinel Federation") -> dict[str, Any]:
    ioc_type = str(indicator.get("ioc_type", ""))
    value_hash = str(indicator.get("value_hash", ""))
    value_ref = indicator.get("value_ref")
    if ioc_type not in SUPPORTED_TYPES:
        raise ValueError("unsupported IOC type")
    if not _SHA256.fullmatch(value_hash):
        raise ValueError("value_hash must be lowercase SHA-256 hex")
    if not isinstance(value_ref, str) or not value_ref:
        raise ValueError("value_ref is required to export an indicator")
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    created = indicator.get("created_at") or now
    modified = indicator.get("last_seen") or created
    return {
        "type": "indicator",
        "spec_version": STIX_VERSION,
        "id": _stix_id("indicator", ioc_type, value_hash),
        "created": created,
        "modified": modified,
        "name": f"Sentinel federated {ioc_type}",
        "description": "Federated threat-intelligence indicator",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "pattern": _pattern_for(ioc_type, value_ref),
        "valid_from": created,
        "labels": [str(indicator.get("category") or "threat-intelligence")],
        "confidence": round(max(0.0, min(1.0, float(indicator.get("confidence", 0.5)))) * 100),
        "external_references": [{"source_name": source_name, "external_id": value_hash}],
    }


def bundle_from_indicators(indicators: Iterable[dict[str, Any]], *, source_name: str = "Sentinel Federation") -> bytes:
    objects = [indicator_to_stix(item, source_name=source_name) for item in indicators]
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid5(NAMESPACE_URL, hashlib.sha256(json.dumps(objects, sort_keys=True, separators=(",", ":")).encode()).hexdigest())}",
        "objects": objects,
    }
    return json.dumps(bundle, separators=(",", ":"), sort_keys=True).encode("utf-8")


def parse_stix_bundle(payload: bytes | str) -> list[dict[str, Any]]:
    try:
        bundle = json.loads(payload)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid STIX JSON") from exc
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("expected STIX bundle")
    result: list[dict[str, Any]] = []
    for obj in bundle["objects"]:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        if obj.get("spec_version") != STIX_VERSION or obj.get("pattern_type") != "stix":
            continue
        pattern = str(obj.get("pattern", ""))
        match = re.fullmatch(r"\[([a-z0-9-]+):(?:hashes\.'SHA-256'|value) = '(.+)'\]", pattern)
        if not match:
            continue
        field, value = match.groups()
        field_map = {
            "file": "sha256",
            "domain-name": "domain",
            "ipv4-addr": "ipv4",
            "ipv6-addr": "ipv6",
            "url": "url",
            "email-addr": "email",
            "x-sentinel-ja3": "ja3",
            "x-sentinel-btc-address": "btc_address",
            "x-sentinel-mutex": "mutex",
        }
        ioc_type = field_map.get(field)
        if not ioc_type:
            continue
        if ioc_type == "sha256" and not _SHA256.fullmatch(value.lower()):
            continue
        external = obj.get("external_references") or []
        value_hash = next((str(ref.get("external_id")) for ref in external if isinstance(ref, dict) and _SHA256.fullmatch(str(ref.get("external_id", "")))), None)
        if not value_hash:
            value_hash = hashlib.sha256(f"{ioc_type}:{value}".encode()).hexdigest()
        result.append({
            "stix_id": obj.get("id"),
            "ioc_type": ioc_type,
            "value_ref": value,
            "value_hash": value_hash,
            "confidence": float(obj.get("confidence", 50)) / 100.0,
            "category": (obj.get("labels") or ["threat-intelligence"])[0],
            "source": "stix",
        })
    return result
