"""Canonical dependency lock validation for reference packs.

Pins are immutable identity/version/content-digest tuples. This module validates
lock material; it does not fetch dependencies or assert that a remote source is trusted.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.-]{1,127}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$")


class DependencyLockError(ValueError):
    pass


def compile_dependency_lock(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"lock_version", "dependencies"}:
        raise DependencyLockError("invalid_lock_shape")
    if value["lock_version"] != 1 or not isinstance(value["dependencies"], list):
        raise DependencyLockError("invalid_lock_version_or_dependencies")
    dependencies = []
    seen: set[str] = set()
    for index, item in enumerate(value["dependencies"]):
        if not isinstance(item, Mapping) or set(item) != {"id", "version", "sha256", "kind"}:
            raise DependencyLockError(f"invalid_dependency_entry:{index}")
        dep_id, version, digest, kind = item["id"], item["version"], item["sha256"], item["kind"]
        if not isinstance(dep_id, str) or not _IDENTIFIER.fullmatch(dep_id):
            raise DependencyLockError(f"invalid_dependency_id:{index}")
        if dep_id in seen:
            raise DependencyLockError(f"duplicate_dependency_id:{dep_id}")
        seen.add(dep_id)
        if not isinstance(version, str) or not _VERSION.fullmatch(version):
            raise DependencyLockError(f"invalid_dependency_version:{dep_id}")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise DependencyLockError(f"invalid_dependency_sha256:{dep_id}")
        if not isinstance(kind, str) or kind not in {"base_policy", "overlay", "compliance_pack", "capability_registry", "runtime_contract"}:
            raise DependencyLockError(f"invalid_dependency_kind:{dep_id}")
        dependencies.append({"id": dep_id, "version": version, "sha256": digest, "kind": kind})
    dependencies.sort(key=lambda item: (item["kind"], item["id"]))
    canonical = json.dumps({"lock_version": 1, "dependencies": dependencies},
                           sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return {
        "lock_version": 1,
        "dependencies": dependencies,
        "lock_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "dependency_count": len(dependencies),
        "status": "pass" if dependencies else "blocked",
        "block_reason": None if dependencies else "empty_dependency_lock",
    }
