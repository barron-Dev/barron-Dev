from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RegistrationAuthority:
    code: str
    jurisdiction: str | None
    name: str
    register_type: str
    source_version: str | None = None


def _first(row: dict[str, Any], *names: str) -> str:
    for name in names:
        value = row.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def parse_gleif_registration_authorities(body: bytes, source_version: str | None = None) -> list[RegistrationAuthority]:
    text = body.decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValueError("GLEIF Registration Authorities CSV has no header")
    headers = {h.strip().lower() for h in reader.fieldnames if h}
    required = {"code", "name"}
    if not required.issubset(headers):
        raise ValueError("GLEIF Registration Authorities CSV is missing required columns")

    result: list[RegistrationAuthority] = []
    seen: set[str] = set()
    for row in reader:
        code = _first(row, "Code", "Register", "RA Code")
        name = _first(row, "Name", "Register Name", "Authority Name")
        if not code or not name:
            continue
        code = code.upper()
        if code in seen:
            raise ValueError(f"Duplicate registration authority code: {code}")
        seen.add(code)
        jurisdiction = _first(row, "Jurisdiction", "Country", "Jurisdiction Code", "Country Code") or None
        register_type = _first(row, "Type", "Register Type", "Authority Type") or "OTHER"
        result.append(RegistrationAuthority(code, jurisdiction, name, register_type, source_version))
    return result


def summarize_registry_catalog(records: list[RegistrationAuthority]) -> dict[str, int]:
    return {"records_seen": len(records), "unique_codes": len({r.code for r in records})}
