from cyclothone.darkweb.scheduler import _progress_percent


def test_progress_uses_actual_processed_record_ratio() -> None:
    assert _progress_percent(0, 60) == 0
    assert _progress_percent(1, 60) == 1
    assert _progress_percent(30, 60) == 50
    assert _progress_percent(59, 60) == 98
    assert _progress_percent(60, 60) == 100


def test_progress_clamps_invalid_boundaries() -> None:
    assert _progress_percent(-1, 60) == 0
    assert _progress_percent(61, 60) == 100


def test_empty_source_completion_does_not_claim_findings_exist() -> None:
    assert _progress_percent(0, 0) == 100
    assert _progress_percent(1, 0) == 0
