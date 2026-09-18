from datetime import UTC, datetime
from uuid import uuid4

import pytest

from cyclothone.data_trust.models import TransferDecision, TransferRequest


def test_transfer_request_normalizes_supported_aliases() -> None:
    request = TransferRequest(
        tenant_id=uuid4(), asset_id=None, device_id=None, actor_id=None,
        source_type="endpoint", destination_type="flash drive", destination_ref=None,
        destination_trust="unknown", bytes_transferred=10, content_inspected=False,
        content_hash=None, observed_at=datetime.now(UTC),
    )
    assert request.destination_type == "removable_media"


def test_transfer_request_rejects_naive_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        TransferRequest(
            tenant_id=uuid4(), asset_id=None, device_id=None, actor_id=None,
            source_type="endpoint", destination_type="cloud", destination_ref=None,
            destination_trust="trusted", bytes_transferred=0, content_inspected=False,
            content_hash=None, observed_at=datetime.now(),
        )


def test_transfer_request_rejects_invalid_content_hash() -> None:
    with pytest.raises(ValueError, match="SHA-256"):
        TransferRequest(
            tenant_id=uuid4(), asset_id=None, device_id=None, actor_id=None,
            source_type="endpoint", destination_type="cloud", destination_ref=None,
            destination_trust="trusted", bytes_transferred=0, content_inspected=False,
            content_hash="not-a-sha256", observed_at=datetime.now(UTC),
        )


def test_transfer_decision_rejects_unknown_decision() -> None:
    with pytest.raises(ValueError, match="invalid transfer decision"):
        TransferDecision("deny", (), None, None)
