from __future__ import annotations
import hashlib
import pytest
from cyclothone.mdi_ingestion.telecom_registry import parse_registry_csv, TelecomRegistryError

def test_registry_csv_parses_realistic_rows_and_binds_source_hash():
    raw = b"mcc,mnc,country_iso,provider_name\n424,02,AE,Example Licensed Operator\n310,260,US,Example US Operator\n"
    rows, digest = parse_registry_csv(raw)
    assert digest == hashlib.sha256(raw).hexdigest()
    assert len(rows) == 2
    assert rows[0]["mcc"] == "424"
    assert rows[0]["mnc"] == "02"
    assert rows[0]["source_sha256"] == digest

@pytest.mark.parametrize("raw", [
    b"mcc,mnc,country_iso,provider_name\n42,02,AE,Invalid MCC\n",
    b"mcc,mnc,country_iso,provider_name\n424,2,AE,Invalid MNC\n",
    b"mcc,mnc,country_iso,provider_name\n424,02,ARE,Invalid ISO\n",
    b"mcc,mnc,country_iso,provider_name\n424,02,AE,First\n424,02,AE,Duplicate\n",
    b"mcc,mnc,country_iso,provider_name\n",
])
def test_registry_rejects_invalid_or_duplicate_rows(raw):
    with pytest.raises(TelecomRegistryError):
        parse_registry_csv(raw)

def test_registry_rejects_empty_and_oversized_input():
    with pytest.raises(TelecomRegistryError):
        parse_registry_csv(b"")
    with pytest.raises(TelecomRegistryError):
        parse_registry_csv(b"x" * (10 * 1024 * 1024 + 1))
