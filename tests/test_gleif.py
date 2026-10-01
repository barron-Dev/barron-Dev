from src.cyclothone.giril.gleif import normalize_lei_record


def test_normalize_gleif_level_one_record():
    row = normalize_lei_record({
        "lei": "506700GE1G29325QX363",
        "entity": {
            "legalName": {"name": "Example Foundation"},
            "status": "ACTIVE",
            "legalAddress": {"country": "CH"},
            "registeredAt": {"id": "RA000001", "other": "123"},
            "legalForm": {"id": "XX"},
        },
    }, "v1", "a" * 64, "source")
    assert row["lei"] == "506700GE1G29325QX363"
    assert row["legal_name"] == "Example Foundation"
    assert row["jurisdiction_country_iso2"] == "CH"
