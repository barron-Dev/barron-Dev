from cyclothone.security_state.parse_target import normalize_target, parse_target

def test_parse_target_from_description():
    assert parse_target("Target: example.com\nService objective: review exposure") == "example.com"

def test_parse_target_does_not_guess_multiline_text():
    assert parse_target("unstructured note\nsecond line") is None

def test_normalize_target_removes_url_path_and_www():
    assert normalize_target("https://www.example.com/path?q=1") == "example.com"

def test_normalize_target_rejects_whitespace():
    assert normalize_target("example .com") == ""
