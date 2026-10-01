from __future__ import annotations

from dataclasses import asdict
from typing import Any, Callable, Iterable, TypeVar

from .registries import RegistrationAuthority

T = TypeVar("T")


def validate_registry_batch(records: Iterable[RegistrationAuthority]) -> list[RegistrationAuthority]:
    materialized = list(records)
    if not materialized:
        raise ValueError("Authoritative registry batch is empty")
    codes: set[str] = set()
    for record in materialized:
        if not record.code or not record.name:
            raise ValueError("Registry records require code and name")
        if record.code in codes:
            raise ValueError(f"Duplicate registry code: {record.code}")
        codes.add(record.code)
    return materialized


def build_registry_rows(records: Iterable[RegistrationAuthority], source_id: str) -> list[dict[str, Any]]:
    valid = validate_registry_batch(records)
    rows = []
    for record in valid:
        rows.append({
            "registry_key": f"GLEIF_RA:{record.code}",
            "registry_name": record.name,
            "registry_type": record.register_type if record.register_type in {"COMPANY", "BUSINESS", "NONPROFIT", "SECURITIES", "TAX", "PROFESSIONAL", "GOVERNMENT", "OTHER"} else "OTHER",
            "authority_level": "OFFICIAL",
            "public_lookup_available": False,
            "api_available": False,
            "source_id": source_id,
            "status": "UNINITIALIZED",
        })
    return rows
