"""Canonical source taxonomy for Cyclothone Dark Web Monitoring.

Layer describes the access path used to observe evidence, not how sensational
or illicit the content may be. A public web preview remains surface web even
when it discusses criminal activity.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Layer = Literal["dark", "surface"]
Availability = Literal["implemented", "historical_only", "planned"]


@dataclass(frozen=True, slots=True)
class SourceDefinition:
    source_id: str
    category: str
    layer: Layer
    access_mode: str
    availability: Availability
    requires_external_credential: bool
    description: str


SOURCE_CATALOG: dict[str, SourceDefinition] = {
    "native_onion": SourceDefinition(
        "native_onion", "onion_site", "dark", "tor_public_onion",
        "implemented", False,
        "Cyclothone native bounded crawler for reviewed public onion URLs; coverage is limited to configured/discovered reachable sources.",
    ),
    "telegram_public": SourceDefinition(
        "telegram_public", "messaging_platform", "surface", "public_web",
        "implemented", False,
        "Public Telegram web previews only; not private groups and not classified as dark web.",
    ),
    "pastebin_public": SourceDefinition(
        "pastebin_public", "paste_site", "surface", "public_web",
        "implemented", False,
        "Public paste feed and validated public paste content.",
    ),
    "ransomwatch": SourceDefinition(
        "ransomwatch", "ransomware_leak_feed", "dark", "public_feed",
        "historical_only", False,
        "Archived/historical feed only until a live pull is independently verified; never count as a fresh check.",
    ),
    "github_code": SourceDefinition(
        "github_code", "code_repository", "surface", "public_api",
        "planned", True,
        "Surface-web code search; optional credentialed connector and not required by native onion collection.",
    ),
    "hibp": SourceDefinition(
        "hibp", "breach_corpus", "surface", "vendor_api",
        "planned", True,
        "Optional external breach-corpus connector; never required for native Cyclothone collection.",
    ),
}

# Explicit product exclusion: Reddit is not a source and must not be registered,
# polled, included in source coverage, or used as a finding origin.
EXCLUDED_SOURCE_IDS = frozenset({"reddit", "reddit_public", "reddit_monitor"})
EXCLUDED_SOURCE_HOSTS = frozenset({"reddit.com", "www.reddit.com", "old.reddit.com", "redd.it"})


def get_source(source_id: str) -> SourceDefinition | None:
    key = str(source_id).strip().lower()
    if key in EXCLUDED_SOURCE_IDS:
        return None
    return SOURCE_CATALOG.get(key)


def is_excluded_source(source_id: str, host: str | None = None) -> bool:
    if str(source_id).strip().lower() in EXCLUDED_SOURCE_IDS:
        return True
    return str(host or "").strip().lower().rstrip(".") in EXCLUDED_SOURCE_HOSTS


def sources_for_layer(layer: Layer, *, include_planned: bool = False) -> tuple[SourceDefinition, ...]:
    return tuple(
        source for source in SOURCE_CATALOG.values()
        if source.layer == layer and (include_planned or source.availability != "planned")
    )


def reportable_as_checked(source_id: str, outcome: str) -> bool:
    """Only a real completed attempt can count as checked; historical feeds never do."""
    source = get_source(source_id)
    return bool(source and source.availability == "implemented" and outcome == "checked")
