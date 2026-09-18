from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sentinel.reports.models import ReportIR
from sentinel.storage.supabase_client import supabase


class ReportBuilder:
    @classmethod
    async def build(cls, tenant_id: UUID, case_id: UUID, agency: str) -> ReportIR:
        case = await cls._one("crime_cases", tenant_id=tenant_id, id=case_id)
        timeline = await cls._many("case_timeline", case_id=case_id, order="ts")
        actions = await cls._many("case_actions", case_id=case_id, order="created_at")
        tenant = await cls._one("tenants", id=tenant_id, fields="name", required=False)
        iocs = await cls._load_iocs(case.get("ioc_ids") or [])
        created_at = _dt(case.get("created_at"))
        return ReportIR(
            case_number=str(case.get("case_number", case_id)), title=str(case.get("title", "Sentinel case")),
            category=str(case.get("category", "unknown")), severity=str(case.get("severity", "unknown")),
            status=str(case.get("status", "unknown")), created_at=created_at,
            tenant_name=str((tenant or {}).get("name", "Unknown")), agency=agency,
            summary=str(case.get("summary") or ""), timeline=timeline, iocs=iocs,
            wallets=list(case.get("wallets") or []), evidence=list(case.get("evidence") or []), actions=actions,
            financial_loss=float(case["financial_loss"]) if case.get("financial_loss") is not None else None,
            currency=case.get("currency"), contact=dict(case.get("contact") or {}),
        )

    @staticmethod
    async def _one(table: str, *, fields: str = "*", required: bool = True, **filters) -> dict | None:
        async def query():
            client = await supabase._ensure()
            q = client.table(table).select(fields)
            for key, value in filters.items(): q = q.eq(key, str(value))
            return await q.limit(1).execute()
        resp = await supabase._retry(query)
        rows = resp.data or []
        if not rows and required: raise RuntimeError("case not found")
        return rows[0] if rows else None

    @staticmethod
    async def _many(table: str, *, order: str, **filters) -> list[dict]:
        async def query():
            client = await supabase._ensure()
            q = client.table(table).select("*")
            for key, value in filters.items(): q = q.eq(key, str(value))
            return await q.order(order, desc=False).execute()
        return list((await supabase._retry(query)).data or [])

    @staticmethod
    async def _load_iocs(ids: list[str]) -> list[dict]:
        if not ids: return []
        async def query():
            client = await supabase._ensure()
            return await client.table("indicators").select("ioc_type,value,severity,confidence,source,tags").in_("id", ids).execute()
        return list((await supabase._retry(query)).data or [])


def _dt(value: object) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if value:
        text = str(value).replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc)
