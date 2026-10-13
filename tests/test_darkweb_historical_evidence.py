from cyclothone.darkweb.request_worker import _merge_evidence_for_findings


def test_historical_findings_get_evidence_reference_without_duplicate_hashes():
    existing = [
        {
            "source": "current-source",
            "content_hash": "hash-current",
            "source_url": "https://example.com/current",
            "label": "new match",
        }
    ]
    findings = [
        {
            "id": "f1",
            "source_id": "historical-source",
            "content_hash": "hash-historical",
            "source_url": "https://example.com/history",
            "first_seen": "2026-10-01T00:00:00Z",
        },
        {
            "id": "f2",
            "source_id": "different-source",
            "content_hash": "hash-current",
            "source_url": "https://example.com/duplicate",
        },
    ]

    merged = _merge_evidence_for_findings(existing, findings)

    by_hash = {row["content_hash"]: row for row in merged}
    assert set(by_hash) == {"hash-current", "hash-historical"}
    assert by_hash["hash-current"]["source_url"] == "https://example.com/current"
    assert by_hash["hash-historical"]["source"] == "historical-source"
    assert by_hash["hash-historical"]["collected_at"] == "2026-10-01T00:00:00Z"
    assert by_hash["hash-historical"]["label"] == "historical match — review"


def test_historical_evidence_url_is_sanitized():
    merged = _merge_evidence_for_findings(
        [],
        [{
            "id": "f1",
            "source_id": "source",
            "content_hash": "hash",
            "source_url": "https://example.com/path Appended title",
        }],
    )

    assert merged[0]["source_url"] is None
