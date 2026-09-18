from cyclothone.timemachine.json_patch import JSONPatch


def test_diff_is_deterministic_and_round_trips():
    old = {"b": 2, "nested": {"z": 1, "a": 3}, "items": [1, 2]}
    new = {"b": 4, "nested": {"a": 3, "c": True}, "items": [1, 2, 3]}
    ops1 = JSONPatch.diff(old, new)
    ops2 = JSONPatch.diff(old, new)
    assert ops1 == ops2
    assert JSONPatch.apply(old, ops1) == new


def test_patch_rejects_ambiguous_keys_and_invalid_traversal():
    try:
        JSONPatch.diff({"bad.key": 1}, {})
        assert False, "expected invalid state key"
    except ValueError:
        pass
    try:
        JSONPatch.apply({"a": 1}, [{"op": "set", "path": "$.a.b", "value": 2}])
        assert False, "expected non-object traversal rejection"
    except ValueError:
        pass


def test_patch_deletes_missing_key_without_mutating_input():
    source = {"a": {"b": 1}}
    result = JSONPatch.apply(source, [{"op": "del", "path": "$.a.missing"}])
    assert result == source
    assert result is not source
