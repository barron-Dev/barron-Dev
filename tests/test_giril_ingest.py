import pytest
from src.cyclothone.giril.ingest import build_registry_rows, validate_registry_batch
from src.cyclothone.giril.registries import RegistrationAuthority


def test_empty_batch_fails_closed():
    with pytest.raises(ValueError):
        validate_registry_batch([])


def test_registry_rows_remain_uninitialized_until_connector_exists():
    records = [RegistrationAuthority("RA000001", "AE", "Example Register", "COMPANY", "1.9")]
    rows = build_registry_rows(records, "source-1")
    assert rows[0]["registry_key"] == "GLEIF_RA:RA000001"
    assert rows[0]["status"] == "UNINITIALIZED"
    assert rows[0]["api_available"] is False


def test_duplicate_batch_fails_closed():
    records = [
        RegistrationAuthority("RA000001", "AE", "One", "COMPANY"),
        RegistrationAuthority("RA000001", "AE", "Two", "COMPANY"),
    ]
    with pytest.raises(ValueError):
        validate_registry_batch(records)
