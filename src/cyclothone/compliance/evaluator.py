from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sentinel.compliance.catalog import CONTROLS
from sentinel.compliance.checks import CHECKS
from sentinel.storage.supabase_client import supabase

logger = logging.getLogger(__name__)

# Automated control results are deliberately short-lived. Historical evidence
# remains immutable, while the current control projection expires after this
# window and must be recollected.
DEFAULT_FRESHNESS_DAYS = 30


class ComplianceEvaluator:
    async def evaluate(self, tenant_id: UUID, framework: str, period_start: datetime, period_end: datetime) -> dict[str, Any]:
        controls = [c for c in CONTROLS if c["framework"] == framework]
        await self._sync_catalog(controls)
        now = datetime.now(UTC)
        valid_until = now + timedelta(days=DEFAULT_FRESHNESS_DAYS)

        async def evaluate_control(control: dict[str, Any]) -> dict[str, Any]:
            check_key = str(control["check_key"])
            check = CHECKS.get(check_key)
            if not check:
                result = ("unknown", 0.0, {"reason": "no automated collector registered", "manual_review": True})
            else:
                try:
                    result = await check(tenant_id, period_start, period_end)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("compliance check %s failed: %s", check_key, exc)
                    result = ("unknown", 0.0, {"reason": "collector error", "error_type": type(exc).__name__})

            status, score, evidence = result
            evidence = {
                **evidence,
                "evaluated_at": now.isoformat(),
                "evidence_valid_until": valid_until.isoformat() if status != "unknown" else None,
                "freshness_window_days": DEFAULT_FRESHNESS_DAYS,
                "freshness_status": "fresh" if status != "unknown" else "unknown",
            }
            db_control = await self._control_row(str(control["id"]))
            if db_control:
                await self._upsert_status({
                    "tenant_id": str(tenant_id),
                    "control_id": db_control["id"],
                    "status": status,
                    "score": score,
                    "last_evaluated": now.isoformat(),
                    "evidence_valid_until": valid_until.isoformat() if status != "unknown" else None,
                    "freshness_status": "fresh" if status != "unknown" else "unknown",
                    "evidence": evidence,
                    "updated_at": now.isoformat(),
                })
            return {**control, "status": status, "score": score, "evidence": evidence, "evidence_valid_until": valid_until.isoformat() if status != "unknown" else None}

        rows = list(await asyncio.gather(*(evaluate_control(c) for c in controls)))
        return self._summary(framework, rows, period_start, period_end)

    async def _sync_catalog(self, controls: list[dict[str, object]]) -> None:
        async def sync_one(c: dict[str, object]) -> None:
            async def _do():
                client = await supabase._ensure()
                return await client.table("compliance_controls").upsert({
                    "stable_id": c["id"], "framework": c["framework"], "control_code": c["code"],
                    "title": c["title"], "description": c["title"], "evidence_sources": c["evidence_sources"],
                }, on_conflict="framework,control_code").execute()
            await supabase._retry(_do, attempts=2)
        await asyncio.gather(*(sync_one(c) for c in controls))

    async def _control_row(self, stable_id: str) -> dict[str, Any] | None:
        async def _do():
            return await (await supabase._ensure()).table("compliance_controls").select("id,stable_id").eq("stable_id", stable_id).limit(1).execute()
        response = await supabase._retry(_do, attempts=2)
        rows = response.data or []
        return rows[0] if rows else None

    async def _upsert_status(self, row: dict[str, Any]) -> None:
        async def _do():
            return await (await supabase._ensure()).table("compliance_control_status").upsert(row, on_conflict="tenant_id,control_id").execute()
        await supabase._retry(_do, attempts=2)

    @staticmethod
    def _summary(framework: str, rows: list[dict[str, Any]], start: datetime, end: datetime) -> dict[str, Any]:
        total = len(rows)
        passing = sum(r["status"] == "passing" for r in rows)
        failing = sum(r["status"] == "failing" for r in rows)
        partial = sum(r["status"] == "partial" for r in rows)
        unknown = sum(r["status"] == "unknown" for r in rows)
        score = sum(float(r["score"]) for r in rows) / total if total else 0.0
        return {"framework": framework, "period_start": start.isoformat(), "period_end": end.isoformat(), "total_controls": total, "passing": passing, "failing": failing, "partial": partial, "unknown": unknown, "overall_score": round(score, 4), "controls": rows}
