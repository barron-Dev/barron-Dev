from __future__ import annotations

import base64
import logging
import os
from dataclasses import asdict
from datetime import datetime, timezone
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cyclothone.chauliodus.graph import EntityGraph
from cyclothone.chauliodus.normalize import NumberNormalizer
from cyclothone.chauliodus.risk import NumberRiskEngine
from cyclothone.storage.supabase_client import supabase

logger = logging.getLogger(__name__)


class ChauliodusEngine:
    """Phone attribution over the tenant-scoped observation graph.

    Physical/network location is never asserted without an authorized
    network-provider signal.
    """

    def __init__(self, tenant_id: UUID, user_id: UUID | None = None) -> None:
        self.tenant_id = tenant_id
        self.user_id = user_id
        self.graph = EntityGraph(tenant_id)
        self.risk = NumberRiskEngine()

    async def attribute(self, raw_number: str, case_id: UUID | None = None) -> dict:
        started = datetime.now(timezone.utc)
        norm = NumberNormalizer.normalize(raw_number)

        async def _rate():
            client = await supabase._ensure()
            return await client.rpc("chauliodus_check_rate", {
                "p_tenant": str(self.tenant_id), "p_limit": 200, "p_window_seconds": 3600,
            }).execute()

        try:
            response = await supabase._retry(_rate, attempts=1)
            if response.data is False:
                raise RuntimeError("attribution rate limit exceeded")
        except RuntimeError:
            raise
        except Exception as exc:
            logger.warning("Chauliodus rate check unavailable: %s", exc)
            raise RuntimeError("attribution rate check unavailable") from exc

        report_count = await self._count_reports(norm.e164_hash)
        campaign_hits = await self._count_campaign_assocs(norm.e164_hash)
        breach_hits = await self._count_breach_hits(norm.e164_hash)
        assessment = self.risk.assess(
            e164=norm.e164, country=norm.country, line_type=norm.line_type,
            carrier_name=norm.carrier, report_count=report_count,
            campaign_associations=campaign_hits, breach_hits=breach_hits,
        )

        entity_id = await self._upsert_entity(norm)
        await self._upsert_number(norm, assessment)
        neighborhood = await self.graph.breadth_first(entity_id, max_depth=2)
        cluster = await self.graph.cluster_score([UUID(n) for n in neighborhood["nodes"][:50]])
        duration_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)

        result = {
            "input": {"raw_hash": NumberNormalizer.hash_value(raw_number),
                      "e164_redacted": NumberNormalizer.redact(norm.e164)},
            "number": {"country": norm.country, "country_code": norm.country_code,
                       "line_type": norm.line_type, "carrier": norm.carrier},
            "risk": asdict(assessment),
            "evidence": {"report_count": report_count,
                         "campaign_associations": campaign_hits, "breach_hits": breach_hits},
            "graph": {"node_count": len(neighborhood["nodes"]),
                      "edge_count": len(neighborhood["edges"]), "cluster_score": cluster},
            "confidence": self._confidence(assessment, cluster, report_count),
            "attribution_note": (
                "Location not asserted: no authorized network API returned geographic "
                "signals. Findings derive from the tenant observation graph and configured intelligence."
            ),
        }
        await self._record(norm.e164_hash, case_id, result, duration_ms)
        return result

    async def _count_reports(self, value_hash: str) -> int:
        async def _do():
            client = await supabase._ensure()
            return await (client.table("scam_reports").select("id", count="exact")
                .eq("tenant_id", str(self.tenant_id)).eq("text_hash", value_hash).limit(1).execute())
        try:
            return int((await supabase._retry(_do, attempts=1)).count or 0)
        except Exception:
            return 0

    async def _count_campaign_assocs(self, value_hash: str) -> int:
        async def _do():
            client = await supabase._ensure()
            return await (client.table("scam_campaigns").select("id", count="exact")
                .eq("tenant_id", str(self.tenant_id)).contains("e164_list", [value_hash]).limit(1).execute())
        try:
            return int((await supabase._retry(_do, attempts=1)).count or 0)
        except Exception:
            return 0

    async def _count_breach_hits(self, value_hash: str) -> int:
        async def _do():
            client = await supabase._ensure()
            return await (client.table("dw_findings").select("id", count="exact")
                .eq("tenant_id", str(self.tenant_id)).eq("content_hash", value_hash).limit(1).execute())
        try:
            return int((await supabase._retry(_do, attempts=1)).count or 0)
        except Exception:
            return 0

    async def _upsert_entity(self, norm) -> UUID:
        encrypted, enc_ref = await self._encrypt_value(norm.e164)
        async def _rpc():
            client = await supabase._ensure()
            return await client.rpc("chauliodus_upsert_entity", {
                "p_tenant": str(self.tenant_id), "p_kind": "phone",
                "p_value_hash": norm.e164_hash, "p_value_redacted": NumberNormalizer.redact(norm.e164),
                "p_value_encrypted": encrypted, "p_encryption_ref": enc_ref,
            }).execute()
        response = await supabase._retry(_rpc)
        if not response.data:
            raise RuntimeError("failed to persist Chauliodus entity")
        return UUID(str(response.data))

    async def _upsert_number(self, norm, assessment) -> None:
        async def _do():
            client = await supabase._ensure()
            return await client.table("chauliodus_numbers").upsert({
                "tenant_id": str(self.tenant_id), "e164": norm.e164, "e164_hash": norm.e164_hash,
                "country": norm.country, "country_code": norm.country_code, "national": norm.national,
                "line_type": norm.line_type, "carrier": norm.carrier,
                "carrier_mcc_mnc": norm.carrier_mcc_mnc,
                "voip_probability": assessment.voip_probability,
                "recycling_score": assessment.recycling_score,
                "fraud_score": assessment.fraud_score,
                "last_seen": datetime.now(timezone.utc).isoformat(),
            }, on_conflict="tenant_id,e164_hash").execute()
        await supabase._retry(_do, attempts=2)

    async def _encrypt_value(self, value: str) -> tuple[str, str]:
        dek = await self._tenant_dek()
        nonce = os.urandom(12)
        ct = AESGCM(dek).encrypt(nonce, value.encode(), str(self.tenant_id).encode())
        ref = f"chauliodus_dek_{str(self.tenant_id)[:8]}"
        return base64.b64encode(nonce + ct).decode(), ref

    async def _tenant_dek(self) -> bytes:
        ref = f"chauliodus_dek_{str(self.tenant_id)[:8]}"
        async def _get():
            return await (await supabase._ensure()).rpc("get_vault_secret", {"p_name": ref}).execute()
        try:
            response = await supabase._retry(_get, attempts=1)
            if isinstance(response.data, str) and response.data:
                key = base64.b64decode(response.data)
                if len(key) == 32:
                    return key
        except Exception:
            pass
        dek = os.urandom(32)
        async def _set():
            return await (await supabase._ensure()).rpc("store_forwarder_secret", {
                "p_tenant": str(self.tenant_id), "p_name": ref,
                "p_secret": base64.b64encode(dek).decode(),
            }).execute()
        await supabase._retry(_set)
        return dek

    async def _record(self, input_hash, case_id, result, duration_ms) -> None:
        async def _do():
            return await (await supabase._ensure()).table("chauliodus_attributions").insert({
                "tenant_id": str(self.tenant_id),
                "requested_by": str(self.user_id) if self.user_id else None,
                "input_kind": "phone", "input_hash": input_hash,
                "case_id": str(case_id) if case_id else None, "status": "complete",
                "result": result, "confidence": result["confidence"], "duration_ms": duration_ms,
                "completed_at": datetime.now(timezone.utc).isoformat(),
            }).execute()
        try:
            await supabase._retry(_do, attempts=1)
        except Exception as exc:
            logger.warning("Chauliodus attribution audit failed: %s", exc)

    @staticmethod
    def _confidence(assessment, cluster: float, reports: int) -> float:
        return round(min(
            0.35 * assessment.fraud_score + 0.25 * cluster +
            0.20 * min(1.0, reports / 10) + 0.20 * assessment.voip_probability, 1.0
        ), 4)
