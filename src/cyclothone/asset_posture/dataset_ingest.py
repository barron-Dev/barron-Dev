"""Safe parser for uploaded surface-web asset-posture datasets.

This module validates and normalizes observations only. It does not contact targets,
write to production, or convert observations into verified live checks.
"""
from __future__ import annotations

import csv
import hashlib
import io
import re
from datetime import date
from typing import Any, Iterable

REQUIRED_COLUMNS = {
    "country", "sector", "organization_id", "domain_hash", "collection_date",
    "certificate_query_status", "certificate_source_available",
    "certificate_fallback_used", "certificate_domain_count", "dns_domain_count",
    "subdomain_count", "total_observed_hostnames", "ipv4_count", "ipv6_count",
    "discovered_ip_count", "internetdb_record_count", "mx_count", "ns_count",
    "has_spf", "spf_status", "spf_policy", "weak_spf", "has_dmarc",
    "dmarc_status", "dmarc_policy", "dmarc_enforced", "self_hosted_mail",
    "observed_asset_coverage", "finding_count", "high_priority_finding_count",
    "posture_score",
}
COUNT_FIELDS = {
    "certificate_domain_count", "dns_domain_count", "subdomain_count",
    "total_observed_hostnames", "ipv4_count", "ipv6_count", "discovered_ip_count",
    "internetdb_record_count", "mx_count", "ns_count", "finding_count",
    "high_priority_finding_count",
}
BOOL_FIELDS = {
    "certificate_source_available", "certificate_fallback_used", "has_spf",
    "weak_spf", "has_dmarc", "dmarc_enforced", "self_hosted_mail",
}
SAFE_SLUG = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,96}$")
SAFE_HASH = re.compile(r"^[a-fA-F0-9]{8,128}$")


class DatasetValidationError(ValueError):
    """The uploaded dataset cannot safely be staged."""


def _boolean(value: str, field: str, row_number: int) -> bool:
    normalized = value.strip().lower()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no"}:
        return False
    raise DatasetValidationError(f"row {row_number}: {field} must be a boolean")


def _integer(value: str, field: str, row_number: int, *, maximum: int = 2**31 - 1) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise DatasetValidationError(f"row {row_number}: {field} must be an integer") from exc
    if parsed < 0 or parsed > maximum:
        raise DatasetValidationError(f"row {row_number}: {field} is outside the allowed range")
    return parsed


def parse_asset_posture_csv(text: str, *, source_label: str = "user_upload") -> dict[str, Any]:
    """Return a sanitized staging envelope; never includes raw domains or IP addresses."""
    if not isinstance(text, str) or not text.strip():
        raise DatasetValidationError("CSV is empty")
    if len(text.encode("utf-8")) > 10 * 1024 * 1024:
        raise DatasetValidationError("CSV exceeds the 10 MiB staging limit")

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise DatasetValidationError("CSV header is missing")
    headers = {header.strip() for header in reader.fieldnames if header}
    missing = sorted(REQUIRED_COLUMNS - headers)
    if missing:
        raise DatasetValidationError("missing required columns: " + ", ".join(missing))

    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for row_number, raw in enumerate(reader, start=2):
        row = {(key or "").strip(): (value or "").strip() for key, value in raw.items()}
        if not any(row.values()):
            continue
        country, sector = row["country"].lower(), row["sector"].lower()
        org_id, domain_hash = row["organization_id"], row["domain_hash"].lower()
        if not SAFE_SLUG.fullmatch(country) or not SAFE_SLUG.fullmatch(sector):
            raise DatasetValidationError(f"row {row_number}: invalid country or sector slug")
        if not SAFE_ID.fullmatch(org_id):
            raise DatasetValidationError(f"row {row_number}: invalid organization_id")
        if not SAFE_HASH.fullmatch(domain_hash):
            raise DatasetValidationError(f"row {row_number}: domain_hash must be a hex digest")
        try:
            collected = date.fromisoformat(row["collection_date"]).isoformat()
        except ValueError as exc:
            raise DatasetValidationError(f"row {row_number}: collection_date must be YYYY-MM-DD") from exc

        identity = (org_id, domain_hash, collected)
        if identity in seen:
            continue
        seen.add(identity)

        normalized: dict[str, Any] = {
            "country": country,
            "sector": sector,
            "organization_id": org_id,
            "domain_hash": domain_hash,
            "collection_date": collected,
        }
        for field in COUNT_FIELDS:
            normalized[field] = _integer(row[field], field, row_number)
        for field in BOOL_FIELDS:
            normalized[field] = _boolean(row[field], field, row_number)
        score = _integer(row["posture_score"], "posture_score", row_number, maximum=100)
        normalized["posture_score"] = score
        for field in (
            "certificate_query_status", "spf_status", "spf_policy", "dmarc_status",
            "dmarc_policy",
        ):
            value = row[field].lower()
            if not value or len(value) > 80:
                raise DatasetValidationError(f"row {row_number}: invalid {field}")
            normalized[field] = value

        coverage = row["observed_asset_coverage"].lower()
        normalized["observed_asset_coverage"] = coverage if coverage else None
        normalized["evidence_quality"] = (
            "fallback_observation" if normalized["certificate_fallback_used"]
            else "source_status_unverified"
        )
        normalized["verification_status"] = "unverified_observation"
        normalized["live_check_performed"] = False
        normalized["source_label"] = source_label
        # No raw hostname, URL, IP, or inferred customer identity is accepted or emitted.
        rows.append(normalized)

    if not rows:
        raise DatasetValidationError("CSV contains no valid data rows")

    canonical = "\n".join(
        f"{r['organization_id']}|{r['domain_hash']}|{r['collection_date']}"
        for r in rows
    )
    return {
        "dataset_type": "surface_web_asset_posture",
        "schema_version": 1,
        "source_label": source_label,
        "record_count": len(rows),
        "deduplicated": True,
        "content_fingerprint_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "identity_fingerprint_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "operational_status": "staged_candidate",
        "production_written": False,
        "live_checks_claimed": False,
        "coverage_claimed": False,
        "records": rows,
    }
