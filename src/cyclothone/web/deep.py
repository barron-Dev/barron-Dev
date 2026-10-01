from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True, slots=True)
class DeepIntelFinding:
    provider: str
    identifier_hash: str
    source_ref: str | None
    severity: str
    metadata: dict[str, Any]


def _hash_identifier(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()


def _safe_metadata(value: dict[str, Any]) -> dict[str, Any]:
    forbidden = {"password", "passwd", "secret", "token", "api_key", "apikey", "cookie", "session", "credential"}
    return {str(k): v for k, v in value.items() if str(k).lower() not in forbidden}


class DeepProvider:
    name = "unknown"

    def __init__(self, *, base_url: str, api_key_env: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key_env = api_key_env

    @property
    def configured(self) -> bool:
        return bool(os.getenv(self.api_key_env))

    async def search(self, identifier: str) -> list[DeepIntelFinding]:
        raise NotImplementedError


class DeHashedProvider(DeepProvider):
    name = "dehashed"

    def __init__(self) -> None:
        super().__init__(base_url=os.getenv("SENTINEL_DEHASHED_URL", "https://api.dehashed.com"), api_key_env="SENTINEL_DEHASHED_KEY")

    async def search(self, identifier: str) -> list[DeepIntelFinding]:
        if not self.configured or not os.getenv("SENTINEL_DEHASHED_EMAIL"):
            return []
        # Deliberately use the provider's documented credentialed search boundary;
        # response credential fields are discarded before entering Sentinel.
        auth = (os.environ["SENTINEL_DEHASHED_EMAIL"], os.environ[self.api_key_env])
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(f"{self.base_url}/search", params={"query": f"email:{identifier}"}, auth=auth)
            response.raise_for_status()
            data = response.json()
        findings: list[DeepIntelFinding] = []
        for item in data.get("entries", [])[:100]:
            metadata = _safe_metadata(item if isinstance(item, dict) else {})
            findings.append(DeepIntelFinding(self.name, _hash_identifier(identifier), str(metadata.get("database")) if metadata.get("database") else None, "high", metadata))
        return findings


class IntelXProvider(DeepProvider):
    name = "intelx"

    def __init__(self) -> None:
        super().__init__(base_url=os.getenv("SENTINEL_INTELX_URL", "https://2.intelx.io"), api_key_env="SENTINEL_INTELX_KEY")

    async def search(self, identifier: str) -> list[DeepIntelFinding]:
        if not self.configured:
            return []
        headers = {"x-key": os.environ[self.api_key_env]}
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(f"{self.base_url}/intelligent/search", params={"term": identifier}, headers=headers)
            response.raise_for_status()
            data = response.json()
        return [DeepIntelFinding(self.name, _hash_identifier(identifier), str(x.get("storageid")) if isinstance(x, dict) else None, "high", _safe_metadata(x if isinstance(x, dict) else {})) for x in data.get("records", [])[:100]]


class SpyCloudProvider(DeepProvider):
    name = "spycloud"

    def __init__(self) -> None:
        super().__init__(base_url=os.getenv("SENTINEL_SPYCLOUD_URL", "https://api.spycloud.com"), api_key_env="SENTINEL_SPYCLOUD_KEY")

    async def search(self, identifier: str) -> list[DeepIntelFinding]:
        if not self.configured:
            return []
        headers = {"Authorization": f"Bearer {os.environ[self.api_key_env]}"}
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(f"{self.base_url}/breach/data", params={"email": identifier}, headers=headers)
            response.raise_for_status()
            data = response.json()
        return [DeepIntelFinding(self.name, _hash_identifier(identifier), str(x.get("id")) if isinstance(x, dict) else None, "high", _safe_metadata(x if isinstance(x, dict) else {})) for x in data.get("results", [])[:100]]


class DeepIntelRegistry:
    def __init__(self, providers: list[DeepProvider] | None = None) -> None:
        self.providers = providers or [DeHashedProvider(), IntelXProvider(), SpyCloudProvider()]

    async def search(self, identifier: str) -> list[DeepIntelFinding]:
        results: list[DeepIntelFinding] = []
        for provider in self.providers:
            if provider.configured:
                results.extend(await provider.search(identifier))
        return results
