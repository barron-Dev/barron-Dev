from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Iterable

@dataclass(frozen=True)
class RiskFactor:
    name: str
    weight: float
    value: float
    detail: str

@dataclass
class RiskVerdict:
    score: float
    band: str
    decision: str
    factors: list[RiskFactor] = field(default_factory=list)
    confidence: float = 0.5
    reasons: list[str] = field(default_factory=list)

class GlobalRiskEnsemble:
    BAND_CRITICAL, BAND_HIGH, BAND_MEDIUM = .85, .65, .40
    def fuse(self, factors: Iterable[RiskFactor]) -> RiskVerdict:
        product, used, reasons = 1.0, [], []
        for f in factors:
            if not 0 <= f.weight <= 1 or not 0 <= f.value <= 1:
                raise ValueError("risk factor weight/value must be within 0..1")
            effective = min(f.weight * f.value, .999)
            if effective > 0:
                product *= 1-effective; used.append(f); reasons.append(f"{f.name}: {f.detail}")
        score = round(min(1-product, 1), 4)
        band = "critical" if score >= .85 else "high" if score >= .65 else "medium" if score >= .40 else "low"
        decision = {"critical":"block","high":"hold","medium":"review","low":"allow"}[band]
        confidence = 0.0 if not used else round(min(.7*min(1, math.log1p(len(used))/math.log(15))+.3*score,.95),4)
        return RiskVerdict(score, band, decision, used, confidence, reasons)

class BaselineTracker:
    ALPHA, MIN_SAMPLES = .05, 20
    def __init__(self) -> None: self._state = {}
    def observe(self, key: str, value: float) -> None:
        s=self._state.setdefault(key,{"mean":0.,"var":1.,"n":0})
        if s["n"] == 0: s["mean"] = value
        else:
            d=value-s["mean"]; s["mean"] += self.ALPHA*d; s["var"]=(1-self.ALPHA)*(s["var"]+self.ALPHA*d*d)
        s["n"] += 1
    def zscore(self,key: str,value: float)->float:
        s=self._state.get(key)
        if not s or s["n"] < self.MIN_SAMPLES: return 0.
        return (value-s["mean"])/math.sqrt(max(s["var"],1e-9))
