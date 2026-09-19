from __future__ import annotations

import hashlib
import re
from pathlib import Path

_VERSION_RE = re.compile(r"^(?P<version>\d+)_.*\.sql$")
_DOWN_RE = re.compile(r"^\d+_.+\.down\.sql$")


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def version_from_name(path: Path) -> str:
    match = _VERSION_RE.match(path.name)
    if not match or _DOWN_RE.match(path.name):
        raise ValueError(
            f"filename must be <numeric>_<name>.sql (up migration): {path.name}"
        )
    return match.group("version").zfill(3)


def human_name(path: Path) -> str:
    stem = path.stem
    parts = stem.split("_", 1)
    return parts[1].replace("_", " ") if len(parts) > 1 else stem
