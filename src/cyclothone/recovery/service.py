from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from typing import Any

from cyclothone.recovery.storage import recovery_storage
from cyclothone.storage.supabase_client import supabase

# Explicit recovery scope. AI tables are intentionally excluded.
RECOVERY_TABLES: tuple[str, ...] = (
    "customer_organizations",
    "tenant_members",
    "devices",
    "events",
    "detections",
    "crime_cases",
    "case_actions",
    "playbooks",
    "playbook_runs",
    "indicators",
    "intel_feeds",
    "dw_findings",
    "dw_alerts",
    "dw_watchlist",
    "brands",
    "brand_threats",
    "physical_sites",
    "camera_events",
    "physical_digital_correlations",
    "hunts",
    "hunt_runs",
    "hunt_schedules",
    "investigation_sessions",
    "investigation_events",
    "investigation_evidence",
    "investigation_iocs",
    "investigation_operations",
    "compliance_attestations",
    "compliance_collection_results",
    "compliance_control_status",
    "compliance_evidence",
    "compliance_evidence_snapshots",
    "compliance_runs",
    "federation_peers",
    "trust_assurance_profiles",
    "trust_attestations",
    "trust_certificates",
    "trust_evidence",
    "trust_measurements",
    "trust_policies",
    "trust_proofs",
    "trust_state_snapshots",
    "audit_log",
)

PAGE_SIZE = 1000


async def _tenant_rows(table: str, tenant_id: str) -> list[dict[str, Any]]:
    client = await supabase._ensure()
    rows: list[dict[str, Any]] = []
    offset = 0

    while True:
        response = await (
            client.table(table)
            .select("*")
            .eq("tenant_id", tenant_id)
            .range(offset, offset + PAGE_SIZE - 1)
            .execute()
        )
        batch = list(response.data or [])
        rows.extend(batch)
        if len(batch) < PAGE_SIZE:
            return rows
        offset += PAGE_SIZE


def _json_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


async def create_full_snapshot(tenant_id: str, region: str) -> dict[str, Any]:
    if not tenant_id:
        raise ValueError("tenant_id is required")
    if not recovery_storage.configured():
        raise RuntimeError("Recovery object storage is not configured")

    started_at = datetime.now(UTC).isoformat()
    snapshot = await supabase.insert_one(
        "recovery_snapshots",
        {
            "tenant_id": tenant_id,
            "region": region,
            "snapshot_type": "full",
            "started_at": started_at,
            "status": "running",
            "object_count": 0,
            "byte_count": 0,
        },
    )
    snapshot_id = str(snapshot["id"])
    manifest: list[dict[str, Any]] = []
    total_bytes = 0

    try:
        for table in RECOVERY_TABLES:
            rows = await _tenant_rows(table, tenant_id)
            if not rows:
                continue

            payload = _json_bytes(
                {
                    "schema_version": 1,
                    "tenant_id": tenant_id,
                    "table": table,
                    "rows": rows,
                }
            )
            key = f"{tenant_id}/snapshots/{snapshot_id}/{table}.json"
            stored = await recovery_storage.put_stream(
                key,
                io.BytesIO(payload),
                content_type="application/json",
            )

            await supabase.insert_one(
                "recovery_objects",
                {
                    "tenant_id": tenant_id,
                    "snapshot_id": snapshot_id,
                    "object_key": stored.key,
                    "sha256": stored.sha256,
                    "size_bytes": stored.size,
                    "content_type": stored.content_type,
                    "encrypted": True,
                },
            )

            manifest.append(
                {
                    "table": table,
                    "object_key": stored.key,
                    "sha256": stored.sha256,
                    "size_bytes": stored.size,
                    "row_count": len(rows),
                }
            )
            total_bytes += stored.size

        manifest_payload = _json_bytes(
            {
                "schema_version": 1,
                "snapshot_id": snapshot_id,
                "tenant_id": tenant_id,
                "region": region,
                "snapshot_type": "full",
                "created_at": started_at,
                "objects": manifest,
            }
        )
        manifest_key = f"{tenant_id}/snapshots/{snapshot_id}/manifest.json"
        manifest_object = await recovery_storage.put_stream(
            manifest_key,
            io.BytesIO(manifest_payload),
            content_type="application/json",
        )

        await supabase.insert_one(
            "recovery_objects",
            {
                "tenant_id": tenant_id,
                "snapshot_id": snapshot_id,
                "object_key": manifest_object.key,
                "sha256": manifest_object.sha256,
                "size_bytes": manifest_object.size,
                "content_type": manifest_object.content_type,
                "encrypted": True,
            },
        )

        await supabase.update(
            "recovery_snapshots",
            {
                "status": "complete",
                "completed_at": datetime.now(UTC).isoformat(),
                "manifest_key": manifest_key,
                "manifest_sha256": manifest_object.sha256,
                "object_count": len(manifest),
                "byte_count": total_bytes,
            },
            id=snapshot_id,
            tenant_id=tenant_id,
        )

        verification = await verify_snapshot(tenant_id, snapshot_id, manifest)
        return {
            "snapshot_id": snapshot_id,
            "status": "complete" if verification["passed"] else "failed",
            "manifest_key": manifest_key,
            "manifest_sha256": manifest_object.sha256,
            "object_count": len(manifest),
            "byte_count": total_bytes,
            "verification": verification,
        }

    except Exception as exc:
        await supabase.update(
            "recovery_snapshots",
            {
                "status": "failed",
                "completed_at": datetime.now(UTC).isoformat(),
                "error_code": "snapshot_failed",
            },
            id=snapshot_id,
            tenant_id=tenant_id,
        )
        raise


async def verify_snapshot(
    tenant_id: str,
    snapshot_id: str,
    manifest: list[dict[str, Any]],
) -> dict[str, Any]:
    checked = 0
    failures = 0

    for item in manifest:
        payload = await recovery_storage.get(str(item["object_key"]))
        import hashlib

        digest = hashlib.sha256(payload).hexdigest()
        checked += 1
        if digest != item["sha256"]:
            failures += 1

    passed = failures == 0
    await supabase.insert_one(
        "recovery_verifications",
        {
            "tenant_id": tenant_id,
            "snapshot_id": snapshot_id,
            "verification_type": "object",
            "passed": passed,
            "checked_count": checked,
            "failure_count": failures,
            "verifier_version": "recovery-v1",
            "details": {"scope": "recovery_object_manifest"},
        },
    )
    return {"passed": passed, "checked_count": checked, "failure_count": failures}
