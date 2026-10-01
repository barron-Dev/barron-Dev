from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from .sources import GleifLeiAdapter


@dataclass(frozen=True)
class VerificationTarget:
    kind: str
    value: str

    @property
    def target_hash(self) -> str:
        return hashlib.sha256(self.value.strip().encode("utf-8")).hexdigest()


_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(value: str) -> str:
    normalized = value.strip().lower()
    if not _EMAIL.fullmatch(normalized):
        raise ValueError("Invalid email format")
    return normalized


def normalize_phone(value: str) -> str:
    normalized = re.sub(r"[\s().-]", "", value.strip())
    if not re.fullmatch(r"\+?[0-9]{7,15}", normalized):
        raise ValueError("Invalid phone format")
    return normalized


def normalize_lei(value: str) -> str:
    normalized = value.strip().upper()
    if not re.fullmatch(r"[A-Z0-9]{20}", normalized):
        raise ValueError("Invalid LEI format")
    return normalized


def build_target(kind: str, value: str) -> VerificationTarget:
    if kind == "EMAIL":
        value = normalize_email(value)
    elif kind == "PHONE":
        value = normalize_phone(value)
    elif kind == "LEI":
        value = normalize_lei(value)
    else:
        raise ValueError(f"Unsupported verification target: {kind}")
    return VerificationTarget(kind, value)


def summarize_gleif(payload: dict[str, Any]) -> dict[str, Any]:
    data = payload.get("data")
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        records = [data]
    else:
        raise ValueError("GLEIF response contains no usable data")

    results = []
    for record in records:
        attrs = record.get("attributes") if isinstance(record, dict) else None
        if not isinstance(attrs, dict):
            continue
        entity = attrs.get("entity") or {}
        registration = attrs.get("registration") or {}
        results.append({
            "lei": attrs.get("lei"),
            "legal_name": (entity.get("legalName") or {}).get("name"),
            "status": attrs.get("entityStatus"),
            "registration_status": registration.get("status"),
            "country": (entity.get("legalAddress") or {}).get("country"),
        })
    return {"records": results, "record_count": len(results)}


def verify_lei(lei: str, adapter: GleifLeiAdapter | None = None) -> dict[str, Any]:
    adapter = adapter or GleifLeiAdapter()
    normalized = normalize_lei(lei)
    return summarize_gleif(adapter.lookup_lei(normalized))
