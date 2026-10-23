"""Canonical source taxonomy for Cyclothone monitoring.

Layer is determined by the route used to observe evidence, not by content
subject matter. Public social-media pages remain surface web; Tor-routed public
.onion sites are the native dark-web layer. A source is reportable only after a
real runtime attempt confirms the outcome.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Layer = Literal["dark", "surface", "surface_historical"]
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
    "native_onion": SourceDefinition("native_onion", "onion_site", "dark", "tor_public_onion", "implemented", False, "Native bounded crawler for reviewed, reachable public onion URLs."),
    "telegram_public": SourceDefinition("telegram_public", "social_media", "surface", "public_web", "implemented", False, "Public Telegram web previews only; never private groups and never dark-web coverage."),
    "pastebin_public": SourceDefinition("pastebin_public", "paste_site", "surface", "public_web", "implemented", False, "Public paste content reachable through the configured public collector."),
    "bluesky_public": SourceDefinition("bluesky_public", "social_media", "surface", "public_api", "implemented", False, "Public Bluesky records through the configured public collector."),
    "github_code": SourceDefinition("github_code", "code_repository", "surface", "public_api", "planned", True, "Optional public code-search connector; not counted unless an actual supported collector succeeds."),
    "ransomwatch": SourceDefinition("ransomwatch", "ransomware_leak_feed", "surface_historical", "public_feed", "implemented", False, "Current public aggregated ransomware-leak feed with dated current entries and separately classified historical records; not direct onion-site verification."),
}

# Explicit exclusion: Reddit is not a source and must not be registered, polled,
# included in coverage, or used as a finding origin. Preserve historic evidence.
EXCLUDED_SOURCE_IDS = frozenset({"reddit", "reddit_public", "reddit_monitor"})
EXCLUDED_SOURCE_HOSTS = frozenset({"reddit.com", "www.reddit.com", "old.reddit.com", "redd.it"})


def get_source(source_id: str) -> SourceDefinition | None:
    key = str(source_id).strip().lower()
    if key in EXCLUDED_SOURCE_IDS:
        return None
    return SOURCE_CATALOG.get(key)


def is_excluded_source(source_id: str, host: str | None = None) -> bool:
    return (str(source_id).strip().lower() in EXCLUDED_SOURCE_IDS or
            str(host or "").strip().lower().rstrip(".") in EXCLUDED_SOURCE_HOSTS)


def sources_for_layer(layer: Layer, *, include_planned: bool = False) -> tuple[SourceDefinition, ...]:
    return tuple(source for source in SOURCE_CATALOG.values()
                 if source.layer == layer and (include_planned or source.availability != "planned"))


def reportable_as_checked(source_id: str, outcome: str) -> bool:
    """Only real successful checks for non-historical sources count as checked."""
    source = get_source(source_id)
    return bool(source and source.availability == "implemented" and outcome == "checked")
