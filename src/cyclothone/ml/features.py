from __future__ import annotations

import math
from typing import Any

import numpy as np

FEATURE_NAMES: list[str] = [
    "entropy", "is_signed", "is_packed", "size_log", "suspicious_imports",
    "network_connections", "child_processes", "file_writes", "registry_writes",
    "mass_file_writes", "encrypts_files", "deletes_shadow_copies",
    "disables_defender", "injects_process", "creates_remote_thread",
    "persistence_registry", "suspicious_parent", "network_beacon", "is_process",
    "is_file", "is_network", "is_registry", "is_sensor", "is_identity",
]


def _num(d: dict[str, Any], key: str, default: float = 0.0) -> float:
    value = d.get(key, default)
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return float(value)
    return default


def extract(event_type: str, payload: dict[str, Any] | None) -> np.ndarray:
    """Return the frozen float32 feature vector shared by training and inference."""
    p = payload or {}
    size_log = math.log1p(max(_num(p, "size"), 0.0))
    kind = (event_type or "").lower()
    vector = [
        _num(p, "entropy"),
        1.0 if p.get("signed") is True else 0.0,
        1.0 if p.get("is_packed") else 0.0,
        size_log,
        float(len(p.get("suspicious_imports") or [])),
        _num(p, "network_connections"), _num(p, "child_processes"),
        _num(p, "file_writes"), _num(p, "registry_writes"),
        1.0 if p.get("mass_file_writes") else 0.0,
        1.0 if p.get("encrypts_files") else 0.0,
        1.0 if p.get("deletes_shadow_copies") else 0.0,
        1.0 if p.get("disables_defender") else 0.0,
        1.0 if p.get("injects_process") else 0.0,
        1.0 if p.get("creates_remote_thread") else 0.0,
        1.0 if p.get("persistence_registry") else 0.0,
        1.0 if p.get("suspicious_parent") else 0.0,
        1.0 if p.get("network_beacon") else 0.0,
        *(1.0 if kind == k else 0.0 for k in ("process", "file", "network", "registry", "sensor", "identity")),
    ]
    return np.nan_to_num(
        np.asarray(vector, dtype=np.float32), nan=0.0, posinf=0.0, neginf=0.0,
    )


if len(FEATURE_NAMES) != 24:  # protects accidental layout drift
    raise RuntimeError("FEATURE_NAMES must contain exactly 24 features")
