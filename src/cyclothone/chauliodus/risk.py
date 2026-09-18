from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class NumberRisk:
    voip_probability: float
    recycling_score: float
    fraud_score: float


class NumberRiskEngine:
    def assess(self, *, e164: str, country: str, line_type: str,
               carrier_name: str | None, report_count: int = 0,
               campaign_associations: int = 0, breach_hits: int = 0) -> NumberRisk:
        line = (line_type or "unknown").lower()
        carrier = (carrier_name or "").lower()
        voip = 0.95 if line == "voip" else 0.0
        if "twilio" in carrier or "vonage" in carrier:
            voip = max(voip, 0.9)
        recycling = min(1.0, max(0, campaign_associations) / 10.0 + max(0, breach_hits) / 20.0)
        fraud = (
            0.45 * min(1.0, max(0, report_count) / 10.0)
            + 0.30 * min(1.0, max(0, campaign_associations) / 3.0)
            + 0.15 * min(1.0, max(0, breach_hits) / 5.0)
            + 0.10 * voip
        )
        return NumberRisk(round(voip, 4), round(recycling, 4), round(min(1.0, fraud), 4))
