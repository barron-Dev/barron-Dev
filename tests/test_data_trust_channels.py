from datetime import UTC, datetime
from uuid import uuid4

from cyclothone.data_trust.channels import normalize_destination, normalize_source
from cyclothone.data_trust.contract import transfer_wire_request
from cyclothone.data_trust.models import TransferRequest


def _request(destination: str) -> TransferRequest:
    return TransferRequest(
        tenant_id=uuid4(), asset_id=None, device_id=None, actor_id=None,
        source_type="endpoint", destination_type=destination,
        destination_ref=None, destination_trust="managed", bytes_transferred=12,
        content_inspected=True, content_hash=None,
        observed_at=datetime.now(UTC), metadata={"channel": destination},
    )


def test_channel_aliases_normalize():
    assert normalize_destination("flash drive") == "removable_media"
    assert normalize_destination("airdrop_peer") == "airdrop"
    assert normalize_destination("web_upload") == "browser"
    assert normalize_source("IM") == "messaging"


def test_unknown_channel_is_not_silently_allowed():
    req = _request("some-new-transport")
    assert req.destination_type == "unknown"


def test_wire_contract_is_json_ready():
    req = _request("bluetooth")
    wire = transfer_wire_request(req)
    assert wire["destination_type"] == "bluetooth"
    assert isinstance(wire["tenant_id"], str)
    assert wire["observed_at"].endswith("+00:00")
