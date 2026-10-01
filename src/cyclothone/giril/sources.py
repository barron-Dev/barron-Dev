from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from .sync import SourceDocument, fetch_document


@dataclass(frozen=True)
class SourceAdapter:
    source_key: str
    def fetch(self) -> SourceDocument:
        raise NotImplementedError


class IanaRootZoneAdapter(SourceAdapter):
    def __init__(self, url: str):
        super().__init__("IANA_ROOT_ZONE")
        self.url = url

    def fetch(self) -> SourceDocument:
        return fetch_document(self.source_key, self.url)


class GleifLeiAdapter(SourceAdapter):
    """Real-time GLEIF LEI lookup adapter; no local mirror or synthetic records."""

    def __init__(self, api_base_url: str = "https://api.gleif.org/api/v1"):
        super().__init__("GLEIF_LEI")
        self.api_base_url = api_base_url.rstrip("/")

    def lookup_lei(self, lei: str) -> dict[str, Any]:
        normalized = lei.strip().upper()
        if len(normalized) != 20 or not normalized.isalnum():
            raise ValueError("LEI must be a 20-character alphanumeric identifier")
        url = f"{self.api_base_url}/lei-records/{normalized}"
        document = fetch_document(self.source_key, url)
        import json
        payload = json.loads(document.body.decode("utf-8"))
        if not isinstance(payload, dict) or "data" not in payload:
            raise ValueError("GLEIF returned an unexpected response shape")
        return payload

    def search_name(self, legal_name: str, page_size: int = 10) -> dict[str, Any]:
        name = legal_name.strip()
        if not name:
            raise ValueError("legal_name is required")
        if not 1 <= page_size <= 100:
            raise ValueError("page_size must be between 1 and 100")
        query = urlencode({"filter[entity.legalName]": name, "page[size]": page_size})
        document = fetch_document(self.source_key, f"{self.api_base_url}/lei-records?{query}")
        import json
        payload = json.loads(document.body.decode("utf-8"))
        if not isinstance(payload, dict) or "data" not in payload:
            raise ValueError("GLEIF returned an unexpected response shape")
        return payload
