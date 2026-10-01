from src.cyclothone.giril.sync import document_json_hash, parse_iana_tlds, SourceDocument


def test_json_hash_is_canonical():
    assert document_json_hash({"b": 2, "a": 1}) == document_json_hash({"a": 1, "b": 2})


def test_iana_parser_ignores_comments_and_normalizes_suffix():
    doc = SourceDocument("IANA_ROOT_ZONE", "https://example.invalid", b"# comment\nCOM\nexample.\n", None, "v1")
    rows = parse_iana_tlds(doc)
    assert [r["domain_suffix"] for r in rows] == ["com", "example"]
    assert all(r["rule_type"] == "PUBLIC_SUFFIX" for r in rows)
