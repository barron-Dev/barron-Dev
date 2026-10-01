from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Iso3166SourcePolicy:
    source_url: str = "https://www.iso.org/iso-3166-country-codes.html"
    auto_download_allowed: bool = False

    def validate_ingest_mode(self, licensed_snapshot: bool) -> None:
        if not licensed_snapshot:
            raise PermissionError(
                "ISO 3166 bulk Country Codes Collection requires the applicable license; "
                "GIRIL will not scrape or redistribute the paid bulk collection."
            )
