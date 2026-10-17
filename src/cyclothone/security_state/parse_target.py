from __future__ import annotations
import re
from urllib.parse import urlsplit

_TARGET = re.compile(r"(?im)^\s*target:\\s*(.+?)\\s*$")

def parse_target(description: str | None) -> str | None:
    if not description:
        return None
    match = _TARGET.search(description)
    if not match:
        return None
    value = match.group(1).strip()
    return value[:500] or None

def normalize_target(target: str) -> str:
    value = target.strip()
    if not value or len(value) > 500:
        return ""
    if value.lower().startswith(("http://", "https://")):
        parsed = urlsplit(value)
        if not parsed.hostname:
            return ""
        value = parsed.hostname
    value = value.rstrip(".").lower()
    if value.startswith("www."):
        value = value[4:]
    if not value or any(c.isspace() for c in value):
        return ""
    return value[:255]
