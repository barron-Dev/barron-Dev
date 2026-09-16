from __future__ import annotations

from sentinel.federation.exchange import _endpoint, _share_value
from sentinel.federation.anon import FederationAnonymizer


def test_endpoint_requires_https_and_public_hostname() -> None:
    try:
        _endpoint({"taxii_url": "http://example.com", "taxii_collection": "c"})
    except ValueError as exc:
        assert "HTTPS" in str(exc)
    else:
        raise AssertionError("non-HTTPS endpoint must be rejected")


def test_sensitive_share_values_are_minimized() -> None:
    anon = FederationAnonymizer(b"x" * 32)
    assert "alice" not in _share_value(anon, "email", "alice@example.com")
    assert _share_value(anon, "ipv4", "192.0.2.44") == "192.0.2.0/24"
    assert _share_value(anon, "url", "https://example.com/a?token=secret") == "https://example.com/a"
    assert _share_value(anon, "domain", "corp.internal").startswith("hmac-sha256:")
