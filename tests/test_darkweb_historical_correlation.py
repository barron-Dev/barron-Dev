from cyclothone.darkweb.request_worker import (
    _alerts_for_findings,
    _merge_result_findings,
)


def test_merge_result_findings_includes_exact_historical_rows_and_deduplicates_ids():
    persisted = [
        {"id": "finding-1", "source_url": "https://example.com/current"},
    ]
    historical = [
        {"id": "finding-1", "source_url": "https://example.com/historical"},
        {"id": "finding-2", "source_url": "https://example.com/older"},
        {"id": None, "source_url": "https://example.com/no-id"},
    ]

    merged = _merge_result_findings(persisted, historical)

    assert [row["id"] for row in merged] == ["finding-1", "finding-2"]
    # Current-watchlist representation wins when the same durable row appears
    # in both collections.
    assert merged[0]["source_url"] == "https://example.com/current"


def test_merge_result_findings_sanitizes_historical_source_urls():
    merged = _merge_result_findings(
        [],
        [
            {"id": "finding-1", "source_url": "https://example.com/path Evidence title"},
            {"id": "finding-2", "source_url": "https://example.com/path"},
        ],
    )

    assert merged[0]["source_url"] is None
    assert merged[1]["source_url"] == "https://example.com/path"


def test_alert_selection_includes_alerts_for_any_result_finding_only():
    findings = [{"id": "current"}, {"id": "historical"}]
    alerts = [
        {"id": "a1", "finding_id": "current"},
        {"id": "a2", "finding_id": "historical"},
        {"id": "a3", "finding_id": "other-tenant-finding"},
        {"id": "a4", "finding_id": None},
    ]

    selected = _alerts_for_findings(alerts, findings)

    assert [row["id"] for row in selected] == ["a1", "a2"]
