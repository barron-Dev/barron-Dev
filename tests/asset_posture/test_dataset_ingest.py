import csv
import io

import pytest

from cyclothone.asset_posture.dataset_ingest import (
    DatasetValidationError,
    REQUIRED_COLUMNS,
    parse_asset_posture_csv,
)


def valid_row():
    row = {name: "0" for name in REQUIRED_COLUMNS}
    row.update({
        "country": "nigeria",
        "sector": "government",
        "organization_id": "NG-GOV-001",
        "domain_hash": "3e6deddff570caae",
        "collection_date": "2026-08-26",
        "certificate_query_status": "fallback",
        "certificate_source_available": "False",
        "certificate_fallback_used": "True",
        "has_spf": "True",
        "spf_status": "valid",
        "spf_policy": "weak_softfail",
        "weak_spf": "True",
        "has_dmarc": "False",
        "dmarc_status": "absent",
        "dmarc_policy": "absent",
        "dmarc_enforced": "False",
        "self_hosted_mail": "False",
        "observed_asset_coverage": "",
        "posture_score": "69",
    })
    return row


def to_csv(rows, columns=None):
    columns = columns or sorted(REQUIRED_COLUMNS)
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def test_parser_stages_observations_without_claiming_live_checks():
    result = parse_asset_posture_csv(to_csv([valid_row()]))
    assert result["dataset_type"] == "surface_web_asset_posture"
    assert result["record_count"] == 1
    assert result["operational_status"] == "staged_candidate"
    assert result["production_written"] is False
    assert result["live_checks_claimed"] is False
    assert result["coverage_claimed"] is False
    assert result["records"][0]["verification_status"] == "unverified_observation"
    assert result["records"][0]["evidence_quality"] == "fallback_observation"
    assert result["records"][0]["posture_score"] == 69


def test_parser_deduplicates_same_org_hash_and_date():
    row = valid_row()
    result = parse_asset_posture_csv(to_csv([row, row]))
    assert result["record_count"] == 1


def test_parser_rejects_missing_required_columns():
    row = valid_row()
    columns = sorted(REQUIRED_COLUMNS - {"domain_hash"})
    with pytest.raises(DatasetValidationError, match="missing required columns"):
        parse_asset_posture_csv(to_csv([row], columns=columns))


@pytest.mark.parametrize("score", ["-1", "101", "not-a-number"])
def test_parser_rejects_invalid_posture_score(score):
    row = valid_row()
    row["posture_score"] = score
    with pytest.raises(DatasetValidationError):
        parse_asset_posture_csv(to_csv([row]))


def test_parser_rejects_invalid_boolean():
    row = valid_row()
    row["has_dmarc"] = "unknown"
    with pytest.raises(DatasetValidationError, match="must be a boolean"):
        parse_asset_posture_csv(to_csv([row]))


def test_parser_rejects_non_digest_domain_hash():
    row = valid_row()
    row["domain_hash"] = "example.com"
    with pytest.raises(DatasetValidationError, match="domain_hash"):
        parse_asset_posture_csv(to_csv([row]))


def test_parser_rejects_empty_input():
    with pytest.raises(DatasetValidationError, match="empty"):
        parse_asset_posture_csv(" ")
