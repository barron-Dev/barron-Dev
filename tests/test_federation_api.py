from __future__ import annotations

import hashlib

from uuid import UUID

import pytest

from sentinel.api.app import create_app
from sentinel.api.routes.federation import IndicatorIngest, PeerCreate, _sanitize_value_ref
from sentinel.federation.anon import FederationAnonymizer
from sentinel.federation.stix import canonical_ioc_hash


def test_federation_router_is_mounted() -> None:
    app = create_app()
    paths = {route.path for route in app.routes}
    assert "/api/v1/federation/peers" in paths
    assert "/api/v1/federation/indicators" in paths
    assert "/api/v1/federation/stix/ingest" in paths
    assert "/api/v1/federation/stix/export" in paths


def test_peer_model_rejects_invalid_kind() -> None:
    with pytest.raises(Exception):
        PeerCreate(name="peer", kind="invalid")


def test_indicator_model_requires_sha256_hex() -> None:
    with pytest.raises(Exception):
        IndicatorIngest(
            peer_id=UUID("00000000-0000-0000-0000-000000000001"),
            ioc_type="domain",
            value_hash="not-a-hash",
        )


def test_direct_indicator_hash_is_canonical() -> None:
    value = "example.com"
    assert canonical_ioc_hash("domain", value) == hashlib.sha256(value.encode()).hexdigest()


def test_anonymizer_requires_strong_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTINEL_FED_SALT", raising=False)
    with pytest.raises(RuntimeError):
        FederationAnonymizer()


def test_sensitive_indicator_values_are_minimized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_FED_SALT", "x" * 32)
    assert _sanitize_value_ref("email", "alice@example.com").endswith("@example.com")
    assert _sanitize_value_ref("ipv4", "192.0.2.44") == "192.0.2.0/24"
    assert _sanitize_value_ref("url", "https://example.com/a?token=secret#frag") == "https://example.com/a"
    assert _sanitize_value_ref("domain", "example.com") == "example.com"


def test_anonymizer_strips_sensitive_url_components(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_FED_SALT", "x" * 32)
    result = FederationAnonymizer().url("https://user:password@example.com/path?q=secret#frag")
    assert result == "https://example.com/path"
    assert "password" not in result
    assert "secret" not in result
