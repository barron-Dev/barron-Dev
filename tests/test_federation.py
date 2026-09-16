from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import pytest

from sentinel.federation.anon import FederationAnonymizer
from sentinel.federation.stix import bundle_from_indicators, indicator_to_stix, parse_stix_bundle


def test_anonymizer_requires_real_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTINEL_FED_SALT", raising=False)
    with pytest.raises(RuntimeError):
        FederationAnonymizer()


def test_anonymizer_minimizes_sensitive_values() -> None:
    anon = FederationAnonymizer(b"x" * 32)
    assert anon.email("alice@example.com").endswith("@example.com")
    assert "alice" not in anon.email("alice@example.com")
    assert anon.ip("192.0.2.44") == "192.0.2.0/24"
    assert anon.ip("2001:db8:1234:5678::1") == "2001:db8:1234::/48"
    assert anon.url("https://example.com/a?token=secret#fragment") == "https://example.com/a"
    assert "password" not in anon.redact_metadata({"password": "secret", "category": "malware"})


def test_stix_round_trip() -> None:
    value = "example.com"
    value_hash = hashlib.sha256(value.encode()).hexdigest()
    indicator = {
        "ioc_type": "domain",
        "value_hash": value_hash,
        "value_ref": value,
        "category": "phishing",
        "confidence": 0.9,
        "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    obj = indicator_to_stix(indicator)
    assert obj["spec_version"] == "2.1"
    bundle = bundle_from_indicators([indicator])
    parsed = parse_stix_bundle(bundle)
    assert len(parsed) == 1
    assert parsed[0]["ioc_type"] == "domain"
    assert parsed[0]["value_ref"] == value
    assert parsed[0]["value_hash"] == value_hash


def test_stix_bundle_is_json() -> None:
    payload = bundle_from_indicators([{
        "ioc_type": "sha256",
        "value_hash": "a" * 64,
        "value_ref": "a" * 64,
    }])
    document = json.loads(payload)
    assert document["type"] == "bundle"
    assert document["objects"][0]["type"] == "indicator"
