import pytest
from src.cyclothone.giril.registries import parse_gleif_registration_authorities, summarize_registry_catalog


def test_parse_gleif_registration_authorities():
    body = b"Code,Name,Jurisdiction,Type\nRA000001,Example Register,AE,COMPANY\nRA000002,Another Register,GB,BUSINESS\n"
    records = parse_gleif_registration_authorities(body, "1.9")
    assert len(records) == 2
    assert records[0].code == "RA000001"
    assert records[0].jurisdiction == "AE"
    assert summarize_registry_catalog(records)["unique_codes"] == 2


def test_registry_catalog_rejects_missing_required_columns():
    with pytest.raises(ValueError):
        parse_gleif_registration_authorities(b"Code,Jurisdiction\nRA000001,AE\n")


def test_registry_catalog_rejects_duplicate_codes():
    with pytest.raises(ValueError):
        parse_gleif_registration_authorities(b"Code,Name\nRA000001,One\nRA000001,Two\n")
