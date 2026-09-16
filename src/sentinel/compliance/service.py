from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sentinel.storage.supabase_client import supabase

FRAMEWORKS = {"soc2", "iso27001", "gdpr", "hipaa"}

# Only metadata-safe, tenant-scoped operational sources are collected. The
# service never copies raw event/evidence payloads into the compliance pack.
SOURCE_FIELDS: dict[str, str] = {
    "detections": "id,created_at,verdict,score,detector",
    "hunt_runs": "id,started_at,status,rows_returned,duration_ms",
    "agent_actions": "id,ts,kind,tool_name,risk_score,blocked",
    "case_actions": "id,created_at,status,action",
    "commands": "id,issued_at,status,action",
    "investigation_events": "id,occurred_at,event_type",
    "data_trust_transfer_events": "id,observed_at,decision,source_type,destination_type",
    "recovery_restore_jobs": "id,created_at,status",
    "residency_audit": "id,created_at,action,region_code",
}


class ComplianceError(ValueError):
    pass


class ComplianceService:
    async def collect(
        self,
        tenant_id: UUID,
        framework: str,
        period_start: datetime,
        period_end: datetime,
        created_by: UUID | None = None,
    ) -> dict[str, Any]:
        self._validate(framework, period_start, period_end)
        run_id = uuid4()
        started = datetime.now(UTC)

        await self._insert("compliance_runs", {
            "id": str(run_id),
            "tenant_id": str(tenant_id),
            "framework": framework,
            "status": "running",
            "period_start": period_start.isoformat(),
            "period_end": period_end.isoformat(),
            "created_by": str(created_by) if created_by else None,
        })

        try:
            controls = await self._controls(framework)
            evidence_count = 0
            covered = 0
            results: list[dict[str, Any]] = []
            for control in controls:
                collected = await self._collect_control(
                    tenant_id, control, period_start, period_end, created_by
                )
                evidence_count += len(collected)
                if collected:
                    covered += 1
                results.append({
                    "control_code": control["control_code"],
                    "title": control["title"],
                    "evidence": collected,
                })

            pack_body = {
                "schema_version": "1.0",
                "framework": framework,
                "tenant_id": str(tenant_id),
                "period": {"start": period_start.isoformat(), "end": period_end.isoformat()},
                "generated_at": datetime.now(UTC).isoformat(),
                "controls": results,
            }
            serialized = json.dumps(pack_body, sort_keys=True, separators=(",", ":")).encode()
            digest = hashlib.sha256(serialized).hexdigest()
            object_ref = f"compliance/{tenant_id}/{framework}/{run_id}.json"

            await self._insert("compliance_packs", {
                "id": str(uuid4()),
                "tenant_id": str(tenant_id),
                "run_id": str(run_id),
                "framework": framework,
                "period_start": period_start.isoformat(),
                "period_end": period_end.isoformat(),
                "status": "ready",
                "object_ref": object_ref,
                "sha256": digest,
                "metadata": {"schema_version": "1.0", "bytes": len(serialized)},
            })
            await self._update_run(run_id, {
                "status": "completed",
                "controls_total": len(controls),
                "controls_with_evidence": covered,
                "evidence_count": evidence_count,
                "completed_at": datetime.now(UTC).isoformat(),
            })
            return {
                "run_id": str(run_id),
                "framework": framework,
                "controls_total": len(controls),
                "controls_with_evidence": covered,
                "evidence_count": evidence_count,
                "sha256": digest,
                "object_ref": object_ref,
                "generated_at": datetime.now(UTC).isoformat(),
            }
        except Exception as exc:
            await self._update_run(run_id, {
                "status": "failed",
                "error": str(exc)[:2000],
                "completed_at": datetime.now(UTC).isoformat(),
            })
            raise

    async def list_frameworks(self, tenant_id: UUID) -> list[dict[str, Any]]:
        # Tenant id is accepted to keep this service's public surface uniform;
        # framework definitions themselves are global reference data.
        del tenant_id
        return await self._select("compliance_controls", "framework,control_code,title,description,evidence_sources", None)

    async def list_packs(self, tenant_id: UUID, framework: str | None = None) -> list[dict[str, Any]]:
        filters = [("tenant_id", str(tenant_id))]
        if framework:
            self._validate_framework(framework)
            filters.append(("framework", framework))
        return await self._select(
            "compliance_packs",
            "id,run_id,framework,period_start,period_end,status,object_ref,sha256,generated_at,metadata",
            filters,
        )

    async def _controls(self, framework: str) -> list[dict[str, Any]]:
        rows = await self._select(
            "compliance_controls",
            "id,framework,control_code,title,description,evidence_sources",
            [("framework", framework)],
        )
        return list(rows)

    async def _collect_control(
        self,
        tenant_id: UUID,
        control: dict[str, Any],
        period_start: datetime,
        period_end: datetime,
        created_by: UUID | None,
    ) -> list[dict[str, Any]]:
        collected: list[dict[str, Any]] = []
        for source in control.get("evidence_sources") or []:
            fields = SOURCE_FIELDS.get(source)
            if not fields:
                continue
            try:
                rows = await self._source_rows(source, fields, tenant_id, period_start, period_end)
            except Exception:
                # A control can still be covered by other authoritative sources.
                continue
            summary = {
                "source": source,
                "row_count": len(rows),
                "first_seen": min((str(r.get("created_at") or r.get("started_at") or r.get("ts") or r.get("observed_at") or r.get("issued_at") or r.get("occurred_at") or r.get("id")) for r in rows), default=None),
                "last_seen": max((str(r.get("created_at") or r.get("started_at") or r.get("ts") or r.get("observed_at") or r.get("issued_at") or r.get("occurred_at") or r.get("id")) for r in rows), default=None),
            }
            canonical = json.dumps(summary, sort_keys=True, separators=(",", ":")).encode()
            evidence = {
                "tenant_id": str(tenant_id),
                "framework": control["framework"],
                "control_id": control["id"],
                "title": f"{control['control_code']} — {source} telemetry summary",
                "evidence_type": "telemetry",
                "source_ref": source,
                "object_ref": None,
                "sha256": hashlib.sha256(canonical).hexdigest(),
                "valid_from": period_start.isoformat(),
                "valid_until": period_end.isoformat(),
                "metadata": summary,
                "collected_by": str(created_by) if created_by else None,
            }
            await self._insert("compliance_evidence", evidence)
            collected.append({"source": source, "sha256": evidence["sha256"], "metadata": summary})
        return collected

    async def _source_rows(self, table: str, fields: str, tenant_id: UUID, start: datetime, end: datetime) -> list[dict[str, Any]]:
        async def _do():
            builder = (await supabase._ensure()).table(table).select(fields).eq("tenant_id", str(tenant_id))
            time_field = {
                "detections": "created_at", "hunt_runs": "started_at", "agent_actions": "ts",
                "case_actions": "created_at", "commands": "issued_at", "investigation_events": "occurred_at",
                "data_trust_transfer_events": "observed_at", "recovery_restore_jobs": "created_at", "residency_audit": "created_at",
            }[table]
            return await builder.gte(time_field, start.isoformat()).lt(time_field, end.isoformat()).limit(1000).execute()
        response = await supabase._retry(_do, attempts=2)
        return list(response.data or [])

    async def _select(self, table: str, fields: str, filters: list[tuple[str, str]] | None) -> list[dict[str, Any]]:
        async def _do():
            builder = (await supabase._ensure()).table(table).select(fields)
            for key, value in filters or []:
                builder = builder.eq(key, value)
            return await builder.limit(5000).execute()
        response = await supabase._retry(_do, attempts=2)
        return list(response.data or [])

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

    @classmethod
    def _validate(cls, framework: str, start: datetime, end: datetime) -> None:
        cls._validate_framework(framework)
        if start.tzinfo is None or end.tzinfo is None:
            raise ComplianceError("period timestamps must include timezone")
        if end <= start:
            raise ComplianceError("period_end must be after period_start")
