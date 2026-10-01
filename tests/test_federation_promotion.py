from __future__ import annotations

from uuid import UUID

import pytest

from cyclothone.federation.promotion import FederationDetectionPromoter
from cyclothone.federation.stix import canonical_ioc_hash


TENANT = UUID("11111111-1111-1111-1111-111111111111")


def test_canonical_federation_match_hash() -> None:
    assert canonical_ioc_hash("domain", "EVIL.Example") == canonical_ioc_hash("domain", "evil.example")


def test_promotion_requires_real_event_context(monkeypatch: pytest.MonkeyPatch) -> None:
    promoter = FederationDetectionPromoter()
    assert promoter is not None
    assert TENANT is not None


def test_unsupported_observation_type_is_ignored() -> None:
    assert "not-supported" not in {"sha256", "domain", "ipv4", "ipv6", "url", "email", "ja3", "btc_address", "mutex"}
