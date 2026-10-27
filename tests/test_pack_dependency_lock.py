import pytest

from cyclothone.packs.dependency_lock import DependencyLockError, compile_dependency_lock


def test_dependency_lock_is_canonical_and_order_independent():
    a = {"lock_version": 1, "dependencies": [
        {"id": "policy_base", "version": "1.2.0", "sha256": "a" * 64, "kind": "base_policy"},
        {"id": "overlay_uae", "version": "3.0.1", "sha256": "b" * 64, "kind": "overlay"},
    ]}
    b = {"lock_version": 1, "dependencies": list(reversed(a["dependencies"]))}
    left, right = compile_dependency_lock(a), compile_dependency_lock(b)
    assert left["lock_sha256"] == right["lock_sha256"]
    assert left["status"] == "pass"


def test_empty_lock_fails_closed():
    result = compile_dependency_lock({"lock_version": 1, "dependencies": []})
    assert result["status"] == "blocked"
    assert result["block_reason"] == "empty_dependency_lock"


@pytest.mark.parametrize("field,value", [
    ("version", "latest"),
    ("sha256", "not-a-hash"),
    ("kind", "unknown"),
])
def test_invalid_pin_is_rejected(field, value):
    item = {"id": "policy_base", "version": "1.0.0", "sha256": "a" * 64, "kind": "base_policy"}
    item[field] = value
    with pytest.raises(DependencyLockError):
        compile_dependency_lock({"lock_version": 1, "dependencies": [item]})


def test_duplicate_dependency_ids_are_rejected_even_with_different_kinds():
    item = {"id": "policy_base", "version": "1.0.0", "sha256": "a" * 64, "kind": "base_policy"}
    other = {"id": "policy_base", "version": "2.0.0", "sha256": "b" * 64, "kind": "overlay"}
    with pytest.raises(DependencyLockError, match="duplicate_dependency_id"):
        compile_dependency_lock({"lock_version": 1, "dependencies": [item, other]})
