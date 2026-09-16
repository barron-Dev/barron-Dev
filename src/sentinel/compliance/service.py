from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sentinel.compliance.catalog import CONTROLS, FRAMEWORKS
from sentinel.compliance.evaluator import ComplianceEvaluator
from sentinel.storage.supabase_client import supabase


class ComplianceError(ValueError):
    pass


class ComplianceService:
    def __init__(self) -> None:
        self.evaluator = ComplianceEvaluator()

    async def list_frameworks(self, tenant_id: UUID) -> list[dict[str, Any]]:
        del tenant_id
        return [{"id": key, **value, "control_count": len([c for c in CONTROLS if c["framework"] == key])} for key, value in FRAMEWORKS.items()]

    async def list_controls(self, tenant_id: UUID, framework: str) -> list[dict[str, Any]]:
        self._validate_framework(framework)
        controls = [c for c in CONTROLS if c["framework"] == framework]

        async def _do():
            return await (await supabase._ensure()).table("compliance_controls").select("id,stable_id,framework,control_code,title,evidence_sources").eq("framework", framework).execute()
        response = await supabase._retry(_do, attempts=2)
        db = {r.get("stable_id"): r for r in (response.data or [])}

        async def _status():
            return await (await supabase._ensure()).table("compliance_control_status").select("control_id,status,score,last_evaluated,evidence").eq("tenant_id", str(tenant_id)).execute()
        status_response = await supabase._retry(_status, attempts=2)
        statuses = {r["control_id"]: r for r in (status_response.data or [])}
        out = []
        for c in controls:
            r = db.get(c["id"])
            s = statuses.get(r["id"]) if r else None
            out.append({**c, "status": s["status"] if s else "unknown", "score": s["score"] if s else 0.0, "last_evaluated": s["last_evaluated"] if s else None, "evidence": s["evidence"] if s else {}})
        return out

    async def evaluate(self, tenant_id: UUID, framework: str, period_start: datetime, period_end: datetime, created_by: UUID | None = None) -> dict[str, Any]:
        self._validate_period(period_start, period_end)
        self._validate_framework(framework)
        run_id = uuid4()
        await self._insert("compliance_runs", {"id": str(run_id), "tenant_id": str(tenant_id), "framework": framework, "status": "running", "period_start": period_start.isoformat(), "period_end": period_end.isoformat(), "created_by": str(created_by) if created_by else None})
        try:
            summary = await self.evaluator.evaluate(tenant_id, framework, period_start, period_end)
            evidence_count = 0
            for control in summary["controls"]:
                for source in control.get("evidence_sources", []):
                    evidence_count += await self._record_evidence(tenant_id, framework, control, source, period_start, period_end, created_by, run_id)
            await self._update_run(run_id, {"status": "completed", "controls_total": summary["total_controls"], "controls_with_evidence": summary["passing"] + summary["partial"], "evidence_count": evidence_count, "completed_at": datetime.now(UTC).isoformat()})
            return {**summary, "run_id": str(run_id), "evidence_count": evidence_count}
        except Exception as exc:
            await self._update_run(run_id, {"status": "failed", "error": str(exc)[:2000], "completed_at": datetime.now(UTC).isoformat()})
            raise

    async def list_packs(self, tenant_id: UUID, framework: str | None = None) -> list[dict[str, Any]]:
        if framework:
            self._validate_framework(framework)
        async def _do():
            q = (await supabase._ensure()).table("compliance_evidence_snapshots").select("id,run_id,framework_id,period_start,period_end,status,overall_score,controls_passing,controls_total,pack_path,pack_sha256,manifest_sha256,signature,signer_kid,evidence_count,verification_status,created_at").eq("tenant_id", str(tenant_id)).order("created_at", desc=True).limit(100)
            if framework:
                q = q.eq("framework_id", framework)
            return await q.execute()
        return list((await supabase._retry(_do, attempts=2)).data or [])

    async def _record_evidence(self, tenant_id: UUID, framework: str, control: dict[str, Any], source: str, start: datetime, end: datetime, created_by: UUID | None, run_id: UUID) -> int:
        field = {"audit_log":"ts","detections":"created_at","devices":None,"data_trust":"observed_at","crime_cases":"created_at","commands":"issued_at","agent_actions":"ts","hunt_runs":"started_at","recovery_vault_policies":None,"recovery_snapshots":"created_at","recovery_restore_jobs":"created_at","residency_audit":"created_at"}.get(source)
        try:
            async def _do():
                q = (await supabase._ensure()).table(source).select("id", count="exact").eq("tenant_id", str(tenant_id))
                if field:
                    q = q.gte(field, start.isoformat()).lt(field, end.isoformat())
                return await q.limit(1).execute()
            response = await supabase._retry(_do, attempts=2)
            count = int(response.count or 0)
        except Exception as exc:  # noqa: BLE001
            await self._record_collection_result(tenant_id, run_id, framework, control, source, "failed", 0, type(exc).__name__, str(exc)[:500], start, end)
            return 0

        stable_id = str(control["id"])
        async def _control():
            return await (await supabase._ensure()).table("compliance_controls").select("id").eq("stable_id", stable_id).limit(1).execute()
        control_rows = (await supabase._retry(_control, attempts=2)).data or []
        if not control_rows:
            await self._record_collection_result(tenant_id, run_id, framework, control, source, "failed", 0, "control_missing", "control catalog row not found", start, end)
            return 0

        canonical = {"tenant_id": str(tenant_id), "framework": framework, "control_id": stable_id, "source": source, "row_count": count, "period_start": start.isoformat(), "period_end": end.isoformat()}
        import hashlib, json
        digest = hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        await self._insert("compliance_evidence", {"tenant_id": str(tenant_id), "framework": framework, "control_id": control_rows[0]["id"], "title": f"{control['code']} — {source} telemetry summary", "evidence_type": "telemetry", "source_ref": source, "sha256": digest, "valid_from": start.isoformat(), "valid_until": end.isoformat(), "collected_at": datetime.now(UTC).isoformat(), "metadata": {"row_count": count, "period_start": start.isoformat(), "period_end": end.isoformat()}, "provenance": {"collector": "sentinel.compliance.service", "run_id": str(run_id), "query_source": source, "tenant_bound": True}, "collected_by": str(created_by) if created_by else None})
        await self._record_collection_result(tenant_id, run_id, framework, control, source, "collected" if count else "empty", count, None, None, start, end)
        return 1

    async def _record_collection_result(self, tenant_id: UUID, run_id: UUID, framework: str, control: dict[str, Any], source: str, result_status: str, row_count: int, error_code: str | None, error_detail: str | None, start: datetime, end: datetime) -> None:
        async def _control():
            return await (await supabase._ensure()).table("compliance_controls").select("id").eq("stable_id", str(control["id"])).limit(1).execute()
        control_rows = (await supabase._retry(_control, attempts=2)).data or []
        await self._insert("compliance_collection_results", {"tenant_id": str(tenant_id), "run_id": str(run_id), "framework": framework, "control_id": control_rows[0]["id"] if control_rows else None, "source_ref": source, "status": result_status, "row_count": row_count, "error_code": error_code, "error_detail": error_detail, "collected_at": datetime.now(UTC).isoformat(), "valid_until": end.isoformat(), "provenance": {"collector": "sentinel.compliance.service", "period_start": start.isoformat(), "period_end": end.isoformat()}})

    async def _insert(self, table: str, row: dict[str, Any]) -> None:
        async def _do():
            return await (await supabase._ensure()).table(table).insert(row).execute()
        await supabase._retry(_do, attempts=2)

    async def _update_run(self, run_id: UUID, patch: dict[str, Any]) -> None:
        async def _do():
            return await (await supabase._ensure()).table("compliance_runs").update(patch).eq("id", str(run_id)).execute()
        await supabase._retry(_do, attempts=2)

    @staticmethod
    def _validate_framework(framework: str) -> None:
        if framework not in FRAMEWORKS:
            raise ComplianceError(f"unsupported framework: {framework}")

    @staticmethod
    def _validate_period(start: datetime, end: datetime) -> None:
        if start.tzinfo is None or end.tzinfo is None or end <= start:
            raise ComplianceError("period must contain timezone-aware timestamps with end after start")
