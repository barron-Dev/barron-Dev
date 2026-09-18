from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Sequence

from .dp import GaussianMechanism, GradientClipper, PrivacyBudget, contribution_commitment

@dataclass(frozen=True)
class TenantContribution:
    round_id: str
    tenant_id: str
    gradient: tuple[float, ...]
    sample_count: int

    def validate(self) -> None:
        if not self.round_id or not self.tenant_id:
            raise ValueError("round and tenant identity are required")
        if self.sample_count < 1:
            raise ValueError("sample_count must be positive")
        if not self.gradient or not all(math.isfinite(x) for x in self.gradient):
            raise ValueError("gradient must be finite and non-empty")

@dataclass(frozen=True)
class AggregatedContribution:
    vector: tuple[float, ...]
    participant_count: int
    commitment_count: int
    commitments: tuple[str, ...]
    clipped_norms: tuple[float, ...]

class FederatedAggregator:
    """Pure, bounded aggregation. Durable persistence belongs to the round service.

    Each tenant contributes at most max_weight after clipping. Sample count can
    influence weight only inside that per-tenant cap, preventing one tenant from
    dominating a federation round.
    """
    def __init__(self, *, clipping_norm: float, budget: PrivacyBudget, max_weight: float = 0.25) -> None:
        if not 0 < max_weight <= 1:
            raise ValueError("max_weight must be in (0,1]")
        self.clipper = GradientClipper(clipping_norm)
        self.mechanism = GaussianMechanism(budget, clipping_norm)
        self.max_weight = max_weight

    def aggregate(self, contributions: Sequence[TenantContribution], minimum_participants: int) -> AggregatedContribution:
        if len(contributions) < minimum_participants:
            raise ValueError("federation quorum not reached")
        seen: set[str] = set()
        clipped: list[tuple[list[float], float, int, str]] = []
        dim: int | None = None
        for c in contributions:
            c.validate()
            if c.tenant_id in seen:
                raise ValueError("duplicate tenant contribution")
            seen.add(c.tenant_id)
            if dim is None:
                dim = len(c.gradient)
            if len(c.gradient) != dim:
                raise ValueError("gradient dimensions do not match")
            vec, norm = self.clipper.clip(list(c.gradient))
            commitment = contribution_commitment(c.round_id, c.tenant_id, vec, c.sample_count)
            clipped.append((vec, norm, c.sample_count, commitment))
        if dim is None:
            raise ValueError("no contributions")
        # Bounded sample-count weighting: raw sample counts determine relative
        # weights, but no tenant may exceed max_weight of the total mass.
        raw = [float(x[2]) for x in clipped]
        total = sum(raw)
        weights = [min(self.max_weight, x / total) for x in raw]
        mass = sum(weights)
        if mass <= 0:
            raise ValueError("invalid aggregation weight mass")
        weights = [w / mass for w in weights]
        result = [0.0] * dim
        for (vec, _, _, _), weight in zip(clipped, weights):
            for i, value in enumerate(vec):
                result[i] += weight * value
        noisy = [self.mechanism.add_noise(x) for x in result]
        if not all(math.isfinite(x) for x in noisy):
            raise ValueError("aggregation produced non-finite output")
        return AggregatedContribution(
            tuple(noisy), len(clipped), len(clipped),
            tuple(x[3] for x in clipped),
            tuple(x[1] for x in clipped),
        )
