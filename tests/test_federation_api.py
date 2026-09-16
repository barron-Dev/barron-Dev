from __future__ import annotations

from uuid import UUID

from sentinel.api.app import create_app
from sentinel.api.routes.federation import IndicatorIngest, PeerCreate


def test_federation_router_is_mounted() -> None:
    app = create_app()
    paths = {route.path for route in app.routes}
    assert "/api/v1/federation/peers" in paths
    assert "/api/v1/federation/indicators" in paths
    assert "/api/v1/federation/stix/ingest" in paths
    assert "/api/v1/federation/stix/export" in paths


def test_peer_model_rejects_invalid_kind() -> None:
    try:
        PeerCreate(name="peer", kind="invalid")
    except Exception:
        return
    raise AssertionError("invalid peer kind must be rejected")


def test_indicator_model_requires_sha256_hex() -> None:
    try:
        IndicatorIngest(
            peer_id=UUID("00000000-0000-0000-0000-000000000001"),
            ioc_type="domain",
            value_hash="not-a-hash",
        )
    except Exception:
        return
    raise AssertionError("invalid indicator hash must be rejected")
