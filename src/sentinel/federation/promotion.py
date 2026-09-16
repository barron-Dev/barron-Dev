from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable
from uuid import UUID

from sentinel.federation.stix import SUPPORTED_TYPES, canonical_ioc_hash
from sentinel.storage.supabase_client import supabase


@dataclass(frozen=True, slots=True)
class FederationMatch:
    indicator_id: UUID
    ioc_type: str
    value_hash: str
    confidence: float
    severity: str


class FederationDetectionPromoter:
    """Promotes verified federation matches into the existing detection pipeline.

    This class deliberately requires event/device context from the normalized
    telemetry pipeline. Federation data alone never manufactures a device,
    event, or case.
    """

    async def find_matches(
        self,
        *,
        tenant_id: UUID,
        observations: Iterable[dict[str, Any]],
        limit: int = 100,
    ) -> list[FederationMatch]:
        if limit < 1 or limit > 100:
            raise ValueError("limit must be between 1 and 100")

        matches: dict[UUID, FederationMatch] = {}
        for observation in observations:
            ioc_type = str(observation.get("ioc_type", ""))
            value = observation.get("value")
            if ioc_type not in SUPPORTED_TYPES or not isinstance(value, str) or not value:
                continue
            try:
                value_hash = canonical_ioc_hash(ioc_type, value)
            except ValueError:
                continue

            async def _lookup() -> Any:
                return await (
                    await supabase._ensure()
                ).table("fed_indicators").select(
                    "id,ioc_type,value_hash,confidence,severity,verified,whitelisted,source_tenant"
                ).eq("ioc_type", ioc_type).eq("value_hash", value_hash).eq(
                    "verified", True
                ).eq("whitelisted", False).or_(
                    f"source_tenant.eq.{tenant_id},source_tenant.is.null"
                ).limit(10).execute()

            rows = (await supabase._retry(_lookup, attempts=2)).data or []
            for row in rows:
                indicator_id = UUID(str(row["id"]))
                matches[indicator_id] = FederationMatch(
                    indicator_id=indicator_id,
                    ioc_type=ioc_type,
                    value_hash=value_hash,
                    confidence=float(row.get("confidence") or 0.5),
                    severity=str(row.get("severity") or "medium"),
                )
                if len(matches) >= limit:
                    return list(matches.values())
        return list(matches.values())

    async def promote(
        self,
        *,
        tenant_id: UUID,
        device_id: UUID,
        event_id: UUID,
        match: FederationMatch,
        observation: dict[str, Any],
    ) -> UUID:
        evidence = {
            "source": "federation",
            "indicator_id": str(match.indicator_id),
            "ioc_type": match.ioc_type,
            "value_hash": match.value_hash,
            "confidence": match.confidence,
            "severity": match.severity,
        }
        if observation.get("source"):
            evidence["observation_source"] = str(observation["source"])

        score = max(0.0, min(1.0, match.confidence))
        if match.severity == "critical":
            score = max(score, 0.95)
        elif match.severity == "high":
            score = max(score, 0.85)

        return UUID(str(await supabase.rpc(
            "promote_fed_match_to_detection",
            {
                "p_tenant_id": str(tenant_id),
                "p_device_id": str(device_id),
                "p_event_id": str(event_id),
                "p_indicator_id": str(match.indicator_id),
                "p_score": score,
                "p_verdict": "malicious",
                "p_reasons": [
                    "verified_federated_indicator_match",
                    f"federated_{match.ioc_type}",
                ],
                "p_evidence": evidence,
            },
        )))

    async def evaluate_event(
        self,
        *,
        tenant_id: UUID,
        device_id: UUID,
        event_id: UUID,
        observations: Iterable[dict[str, Any]],
        limit: int = 100,
    ) -> list[UUID]:
        matches = await self.find_matches(
            tenant_id=tenant_id,
            observations=observations,
            limit=limit,
        )
        if not matches:
            return []

        by_hash = {
            canonical_ioc_hash(str(item.get("ioc_type")), str(item.get("value"))): item
            for item in observations
            if item.get("ioc_type") in SUPPORTED_TYPES and isinstance(item.get("value"), str)
        }
        detections: list[UUID] = []
        for match in matches:
            observation = by_hash.get(match.value_hash)
            if observation is None:
                continue
            detections.append(await self.promote(
                tenant_id=tenant_id,
                device_id=device_id,
                event_id=event_id,
                match=match,
                observation=observation,
            ))
        return detections
