from cyclothone.darkweb.request_worker import _safe_evidence_url


def test_safe_evidence_url_accepts_direct_https_url():
    url = "https://github.com/example/project/blob/main/README.md"
    assert _safe_evidence_url(url) == url


def test_safe_evidence_url_rejects_url_with_appended_title():
    url = "https://github.com/example/project/issues/123 Public report title"
    assert _safe_evidence_url(url) is None


def test_safe_evidence_url_rejects_non_https_and_relative_urls():
    assert _safe_evidence_url("http://example.com/evidence") is None
    assert _safe_evidence_url("/relative/evidence") is None


def test_safe_evidence_url_rejects_credentials_and_invalid_ports():
    assert _safe_evidence_url("https://user:pass@example.com/evidence") is None
    assert _safe_evidence_url("https://example.com:invalid/evidence") is None


def test_safe_evidence_url_rejects_empty_or_non_string_values():
    assert _safe_evidence_url(None) is None
    assert _safe_evidence_url("") is None
