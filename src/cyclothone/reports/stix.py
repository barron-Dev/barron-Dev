from __future__ import annotations

import json
import uuid
from datetime import timezone
from typing import Any

from cyclothone.reports.models import ReportIR


def _stix_id(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(uuid.NAMESPACE_URL, 'cyclothone:' + key)}"


def _pattern(ioc_type: str, value: str) -> str | None:
    safe = value.replace("\\", "\\\\").replace("'", "\\'")
    mapping = {
        "sha256": f"[file:hashes.'SHA-256' = '{safe}']",
        "sha1": f"[file:hashes.'SHA-1' = '{safe}']",
        "md5": f"[file:hashes.MD5 = '{safe}']",
        "domain": f"[domain-name:value = '{safe}']",
        "url": f"[url:value = '{safe}']",
        "ipv4": f"[ipv4-addr:value = '{safe}']",
        "ipv6": f"[ipv6-addr:value = '{safe}']",
        "email": f"[email-addr:value = '{safe}']",
    }
    return mapping.get(ioc_type)


def render_stix21(report: ReportIR) -> bytes:
    now = report.generated_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    identity_id = _stix_id("identity", report.tenant_name)
    malware_id = _stix_id("malware", report.case_number + ":malware")
    objects: list[dict[str, Any]] = [{
        "type": "identity", "spec_version": "2.1", "id": identity_id,
        "created": now, "modified": now, "name": report.tenant_name, "identity_class": "organization",
    }, {
        "type": "malware", "spec_version": "2.1", "id": malware_id,
        "created": now, "modified": now, "name": report.category, "is_family": False, "created_by_ref": identity_id,
    }]
    refs = [malware_id]
    for ioc in report.iocs:
        pattern = _pattern(str(ioc.get("ioc_type", "")), str(ioc.get("value", "")))
        if not pattern:
            continue
        value = str(ioc.get("value", ""))
        iid = _stix_id("indicator", f"{report.case_number}:{ioc.get('ioc_type')}:{value}")
        confidence = ioc.get("confidence")
        obj: dict[str, Any] = {
            "type": "indicator", "spec_version": "2.1", "id": iid, "created": now, "modified": now,
            "name": f"{ioc.get('ioc_type', 'indicator')}: {value[:80]}", "pattern": pattern,
            "pattern_type": "stix", "valid_from": report.created_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "created_by_ref": identity_id,
        }
        if confidence is not None:
            obj["confidence"] = max(0, min(100, round(float(confidence) * 100)))
        objects.append(obj)
        refs.append(iid)
        rid = _stix_id("relationship", iid + ":indicates:" + malware_id)
        objects.append({"type": "relationship", "spec_version": "2.1", "id": rid, "created": now, "modified": now, "relationship_type": "indicates", "source_ref": iid, "target_ref": malware_id, "created_by_ref": identity_id})
        refs.append(rid)
    report_id = _stix_id("report", report.case_number)
    objects.append({
        "type": "report", "spec_version": "2.1", "id": report_id, "created": now, "modified": now,
        "name": f"{report.case_number} - {report.title}", "description": report.summary[:4000],
        "published": report.created_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "report_types": [report.category], "created_by_ref": identity_id, "object_refs": refs,
    })
    return json.dumps({"type": "bundle", "id": _stix_id("bundle", report.case_number), "objects": objects}, separators=(",", ":")).encode("utf-8")
