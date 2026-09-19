from __future__ import annotations

import hashlib
import math
import secrets
from dataclasses import dataclass

@dataclass(frozen=True)
class PrivacyBudget:
    epsilon: float
    delta: float
    def __post_init__(self) -> None:
        if not math.isfinite(self.epsilon) or self.epsilon <= 0:
            raise ValueError("epsilon must be finite and > 0")
        if not math.isfinite(self.delta) or not 0 < self.delta < 1:
            raise ValueError("delta must be finite and in (0,1)")

class GaussianMechanism:
    def __init__(self, budget: PrivacyBudget, sensitivity: float) -> None:
        if not math.isfinite(sensitivity) or sensitivity <= 0:
            raise ValueError("sensitivity must be finite and > 0")
        self.budget = budget
        self.sensitivity = sensitivity

    def sigma(self) -> float:
        # Conservative standard Gaussian calibration for (epsilon, delta).
        return self.sensitivity * math.sqrt(2.0 * math.log(1.25 / self.budget.delta)) / self.budget.epsilon

    def noise(self) -> float:
        # DP noise requires fresh cryptographic randomness; deterministic seeds
        # are deliberately not used as a privacy mechanism.
        return secrets.SystemRandom().gauss(0.0, self.sigma())

    def add_noise(self, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("value must be finite")
        return value + self.noise()

class GradientClipper:
    def __init__(self, max_norm: float) -> None:
        if not math.isfinite(max_norm) or max_norm <= 0:
            raise ValueError("max_norm must be finite and > 0")
        self.max_norm = max_norm

    def clip(self, vector: list[float]) -> tuple[list[float], float]:
        if not vector or not all(math.isfinite(x) for x in vector):
            raise ValueError("gradient must be non-empty and finite")
        norm = math.sqrt(sum(x * x for x in vector))
        if not math.isfinite(norm):
            raise ValueError("gradient norm is non-finite")
        scale = min(1.0, self.max_norm / max(norm, 1e-30))
        clipped = [x * scale for x in vector]
        return clipped, math.sqrt(sum(x * x for x in clipped))

def contribution_commitment(round_id: str, tenant_id: str, vector: list[float], sample_count: int) -> str:
    if not round_id or not tenant_id or sample_count < 1:
        raise ValueError("invalid contribution identity")
    if not vector or not all(math.isfinite(x) for x in vector):
        raise ValueError("invalid contribution vector")
    # Canonical decimal encoding prevents language/runtime-dependent float repr.
    body = ",".join(format(x, ".17g") for x in vector)
    material = f"immune-v1\n{round_id}\n{tenant_id}\n{sample_count}\n{body}".encode()
    return hashlib.sha256(material).hexdigest()
