from datetime import UTC, datetime

import pytest

from cyclothone.compliance.global_intelligence import normalize_epss, normalize_kev


def test_normalize_kev_keeps_only_valid_cve_and_preserves_due_dates():
    now = datetime(2026, 10, 30, tzinfo=UTC)
    rows = normalize_kev({
        "catalogVersion": "2026.10.30",
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-12345",
                "dateAdded": "2026-10-01",
                "dueDate": "2026-10-15",
                "knownRansomwareCampaignUse": "Known",
            },
            {"cveID": "not-a-cve"},
        ],
    }, now)
    assert len(rows) == 1
    assert rows[0]["cve_id"] == "CVE-2024-12345"
    assert rows[0]["cisa_kev_listed"] is True
    assert rows[0]["known_ransomware_use"] is True


def test_normalize_epss_rejects_out_of_range_and_invalid_scores():
    now = datetime(2026, 10, 30, tzinfo=UTC)
    rows = normalize_epss([
        {"cve": "CVE-2025-1234", "epss": "0.75", "percentile": "0.99", "date": "2026-10-30"},
        {"cve": "CVE-2025-1235", "epss": "1.2", "percentile": "0.9"},
        {"cve": "CVE-2025-1236", "epss": None, "percentile": "0.5"},
    ], now)
    assert len(rows) == 1
    assert rows[0]["epss_score"] == 0.75
    assert rows[0]["epss_percentile"] == 0.99
    assert rows[0]["epss_as_of"] == "2026-10-30"


def test_feed_missing_data_is_not_normalized_as_zero_risk():
    now = datetime(2026, 10, 30, tzinfo=UTC)
    with pytest.raises(ValueError, match="missing_vulnerabilities"):
        normalize_kev({"catalogVersion": "bad"}, now)
