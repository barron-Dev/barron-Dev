from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sentinel.compliance.catalog import FRAMEWORKS
from sentinel.compliance.freshness import coverage_summary
from sentinel.compliance.signing import sign_digest
from sentinel.storage.supabase_client import supabase


class EvidencePackBuilder:
    async def build(self, tenant_id: UUID, framework: str, period_days: int = 90, generated_by: UUID | None = None) -> dict:
        if framework not in FRAMEWORKS:
            raise ValueError(f"unsupported framework: {framework}")
        if not 7 <= period_days <= 730:
            raise ValueError("period_days must be between 7 and 730")

        end = datetime.now(UTC)
        start = end - timedelta(days=period_days)
        controls = await self._controls(framework)
        statuses = await self._statuses(tenant_id, framework)
        evidence = await self._evidence(tenant_id, framework, start, end)
        collection_results = await self._collection_results(tenant_id, framework, start)
        coverage = self._coverage(controls, collection_results)
        attestations = await self._attestations(tenant_id, start)
        audit = await self._audit(tenant_id, start, end)

        body = {
            "schema_version": "1.2",
            "generated_at": end.isoformat(),
            "tenant_id": str(tenant_id),
            "framework": FRAMEWORKS[framework],
            "framework_id": framework,
            "period": {"start": start.isoformat(), "end": end.isoformat()},
            "controls": controls,
            "control_status": statuses,
            "evidence": evidence,
            "collection_results": collection_results,
            "evidence_coverage": coverage,
            "attestations": attestations,
            "audit_extract": audit,
        }
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()
        manifest_sha = hashlib.sha256(canonical).hexdigest()
        signature = await sign_digest(manifest_sha)
        manifest = {**body, "manifest_sha256": manifest_sha, "signature": signature.signature_b64, "signer_kid": signature.kid}

        files = {
            "manifest.json": json.dumps(manifest, sort_keys=True, indent=2, default=str).encode(),
            "controls.json": json.dumps(controls, indent=2, default=str).encode(),
            "control_status.json": json.dumps(statuses, indent=2, default=str).encode(),
            "evidence.json": json.dumps(evidence, indent=2, default=str).encode(),
            "collection_results.json": json.dumps(collection_results, indent=2, default=str).encode(),
            "evidence_coverage.json": json.dumps(coverage, indent=2, default=str).encode(),
            "attestations.json": json.dumps(attestations, indent=2, default=str).encode(),
            "audit_extract.json": json.dumps(audit, indent=2, default=str).encode(),
            "README.txt": self._readme(framework, start, end).encode(),
        }
        file_hashes = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
        files["file_hashes.json"] = json.dumps(file_hashes, sort_keys=True, indent=2).encode()

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for name, data in files.items():
                z.writestr(name, data)
        pack = buf.getvalue()
        pack_sha = hashlib.sha256(pack).hexdigest()
        object_ref = f"{tenant_id}/{framework}/{pack_sha[:16]}.zip"

        await self._upload(object_ref, pack)
        passing = sum(s.get("status") == "passing" for s in statuses)
        total = len(controls)
        score = sum(float(s.get("score", 0)) for s in statuses) / total if total else 0.0
        snapshot = {
            "tenant_id": str(tenant_id), "framework_id": framework,
            "period_start": start.isoformat(), "period_end": end.isoformat(), "status": "ready",
            "overall_score": round(score, 4), "controls_passing": passing, "controls_total": total,
            "pack_path": object_ref, "pack_sha256": pack_sha, "manifest_sha256": manifest_sha,
            "signature": signature.signature_b64, "signer_kid": signature.kid,
            "evidence_count": len(evidence), "verification_status": "unverified",
            "generated_by": str(generated_by) if generated_by else None,
        }
        await self._insert("compliance_evidence_snapshots", snapshot)
        return {"snapshot": snapshot, "framework": framework, "pack_sha256": pack_sha, "manifest_sha256": manifest_sha, "signature": signature.signature_b64, "signer_kid": signature.kid, "object_ref": object_ref, "controls_total": total, "controls_passing": passing, "evidence_count": len(evidence), "overall_score": round(score, 4), "evidence_coverage": coverage}

    async def _controls(self, framework: str) -> list[dict]:
        async def _do():
            return await (await supabase._ensure()).table("compliance_controls").select("id,stable_id,framework,control_code,title,description,evidence_sources").eq("framework", framework).order("control_code").execute()
        return list((await supabase._retry(_do, attempts=2)).data or [])

    async def _statuses(self, tenant_id: UUID, framework: str) -> list[dict]:
        controls = await self._controls(framework)
        ids = {r["id"] for r in controls}
        async def _do():
            return await (await supabase._ensure()).table("compliance_control_status").select("control_id,status,score,last_evaluated,evidence").eq("tenant_id", str(tenant_id)).execute()
        return [r for r in ((await supabase._retry(_do, attempts=2)).data or []) if r["control_id"] in ids]

    async def _evidence(self, tenant_id: UUID, framework: str, start: datetime, end: datetime) -> list[dict]:
        async def _do():
            return await (await supabase._ensure()).table("compliance_evidence").select("id,control_id,title,evidence_type,source_ref,sha256,collected_at,valid_from,valid_until,freshness_window_seconds,stale,metadata,provenance").eq("tenant_id", str(tenant_id)).eq("framework", framework).gte("collected_at", start.isoformat()).lt("collected_at", end.isoformat()).order("collected_at", desc=True).limit(10000).execute()
        return list((await supabase._retry(_do, attempts=2)).data or [])

    async def _collection_results(self, tenant_id: UUID, framework: str, start: datetime) -> list[dict]:
        async def _do():
            return await (await supabase._ensure()).table("compliance_collection_results").select("id,run_id,control_id,source_ref,status,row_count,error_code,error_detail,collected_at,valid_from,valid_until,freshness_window_seconds,stale,provenance").eq("tenant_id", str(tenant_id)).eq("framework", framework).gte("collected_at", start.isoformat()).order("collected_at", desc=True).limit(10000).execute()
        return list((await supabase._retry(_do, attempts=2)).data or [])

    @staticmethod
    def _coverage(controls: list[dict], results: list[dict]) -> list[dict]:
        now = datetime.now(UTC)
        by_control: dict[str, list[dict]] = {}
        for row in results:
            by_control.setdefault(str(row.get("control_id")), []).append(row)
        output = []
        for control in controls:
            expected = [str(source) for source in (control.get("evidence_sources") or [])]
            rows = by_control.get(str(control["id"]), [])
            latest = {}
            for row in rows:
                source = str(row.get("source_ref", ""))
                if source and source not in latest:
                    latest[source] = row
            summary = coverage_summary(list(latest.values()), expected)
            summary.update({"control_id": control["id"], "stable_id": control.get("stable_id"), "control_code": control.get("control_code")})
            # Re-evaluate staleness at pack generation time, not only at collection time.
            for source in summary["sources"]:
                row = latest.get(source["source_ref"])
                if row:
                    value = row.get("valid_until")
                    source["stale"] = source["stale"] or (not value) or str(value).replace("Z", "+00:00") <= now.isoformat()
            output.append(summary)
        return output

    async def _attestations(self, tenant_id: UUID, start: datetime) -> list[dict]:
        async def _do():
            return await (await supabase._ensure()).table("compliance_attestations").select("id,control_id,snapshot_id,attested_by,statement,statement_sha256,signature,signer_kid,created_at").eq("tenant_id", str(tenant_id)).gte("created_at", start.isoformat()).execute()
        return list((await supabase._retry(_do, attempts=2)).data or [])

    async def _audit(self, tenant_id: UUID, start: datetime, end: datetime) -> list[dict]:
        async def _do():
            return await (await supabase._ensure()).table("audit_log").select("id,actor,action,resource,resource_id,ts").eq("tenant_id", str(tenant_id)).gte("ts", start.isoformat()).lt("ts", end.isoformat()).order("ts", desc=True).limit(10000).execute()
        try:
            return list((await supabase._retry(_do, attempts=2)).data or [])
        except Exception:
            return []

    async def _upload(self, path: str, data: bytes) -> None:
        async def _do():
            client = await supabase._ensure()
            try:
                return await client.storage.from_("compliance").upload(path, data, {"content-type": "application/zip", "upsert": "false"})
            except Exception:
                try:
                    await client.storage.create_bucket("compliance", {"public": False})
                except Exception:
                    pass
                return await client.storage.from_("compliance").upload(path, data, {"content-type": "application/zip", "upsert": "false"})
        await supabase._retry(_do, attempts=3)

    async def _insert(self, table: str, row: dict) -> None:
        async def _do():
            return await (await supabase._ensure()).table(table).insert(row).execute()
        await supabase._retry(_do, attempts=2)

    @staticmethod
    def _readme(framework: str, start: datetime, end: datetime) -> str:
        return f"Sentinel Compliance Evidence Pack\nFramework: {framework}\nPeriod: {start.isoformat()} to {end.isoformat()}\n\nThe pack records collector coverage and evidence freshness explicitly. Missing, failed, or stale collectors are not treated as successful evidence.\n\nmanifest_sha256 is the signed canonical manifest digest. pack_sha256 is the SHA-256 of the ZIP object. file_hashes.json permits per-file integrity verification.\n\nThis pack contains automated evidence summaries and cryptographic integrity metadata. It is not legal certification or an auditor's opinion.\n"
