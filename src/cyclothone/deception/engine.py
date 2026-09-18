from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any, Mapping
from urllib.parse import quote
from uuid import UUID

from sentinel.deception.models import ArtifactSpec, DeceptionArtifact, TriggerResult, utcnow
from sentinel.storage.supabase_client import supabase


class DeceptionEngine:
    """Create inert deception artifacts and consume their server callbacks.

    Secrets are returned exactly once to the provisioning caller and only a
    SHA-256 digest is stored. Generated credentials are explicitly non-working;
    their purpose is to create high-confidence detection when handled.
    """

    def __init__(self, *, callback_base_url: str) -> None:
        base = callback_base_url.strip().rstrip("/")
        if not base.startswith("https://"):
            raise ValueError("deception callback base URL must use HTTPS")
        self.callback_base_url = base

    async def create(self, spec: ArtifactSpec) -> DeceptionArtifact:
        secret = _secret_for(spec.artifact_type)
        token = "sdc_" + secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        prefix = token[:12]
        callback = f"{self.callback_base_url}/api/v1/deception/callback/{quote(token, safe='')}"
        metadata = dict(spec.metadata)
        metadata.update({"generated_by": "sentinel", "inert": True, "callback_url": callback})

        row = await supabase.insert_one(
            "deception_artifacts",
            {
                "tenant_id": str(spec.tenant_id),
                "artifact_type": spec.artifact_type,
                "name": spec.name,
                "target": spec.target,
                "device_id": str(spec.device_id) if spec.device_id else None,
                "auto_case_rule_id": str(spec.auto_case_rule_id) if spec.auto_case_rule_id else None,
                "token_prefix": prefix,
                "token_hash": token_hash,
                "metadata": metadata,
                "severity": spec.severity,
                "created_by": str(spec.created_by) if spec.created_by else None,
            },
        )
        artifact_id = UUID(str(row["id"]))
        return DeceptionArtifact(
            id=artifact_id,
            tenant_id=spec.tenant_id,
            artifact_type=spec.artifact_type,
            name=spec.name,
            target=spec.target,
            token_prefix=prefix,
            secret=secret,
            callback_url=callback,
            metadata=metadata,
        )

    async def create_honeyfile(self, spec: ArtifactSpec) -> tuple[DeceptionArtifact, bytes]:
        if spec.artifact_type != "honeyfile":
            raise ValueError("create_honeyfile requires artifact_type=honeyfile")
        artifact = await self.create(spec)
        content = _honeyfile_content(artifact, spec.metadata)
        return artifact, content

    async def record_callback(
        self,
        token: str,
        *,
        source_ip: str | None = None,
        forwarded_for: str | None = None,
        user_agent: str | None = None,
        request_method: str | None = None,
        request_path: str | None = None,
        source_country: str | None = None,
        source_asn: int | None = None,
        source_org: str | None = None,
        evidence: Mapping[str, Any] | None = None,
    ) -> TriggerResult | None:
        if not token.startswith("sdc_"):
            return None
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        rows = await supabase.rpc("deception_record_trigger", {
            "p_token_hash": token_hash,
            "p_source_ip": source_ip,
            "p_forwarded_for": forwarded_for,
            "p_user_agent": user_agent,
            "p_request_method": request_method,
            "p_request_path": request_path,
            "p_source_country": source_country,
            "p_source_asn": source_asn,
            "p_source_org": source_org,
            "p_evidence": dict(evidence or {}),
        })
        if not rows:
            return None
        row = rows[0]
        trigger_id = UUID(str(row["trigger_id"]))
        finalized = await supabase.rpc("deception_finalize_trigger", {"p_trigger_id": str(trigger_id)})
        final = finalized[0] if finalized else {}
        return TriggerResult(
            trigger_id=trigger_id,
            tenant_id=UUID(str(row["tenant_id"])),
            artifact_id=UUID(str(row["artifact_id"])),
            artifact_type=str(row["artifact_type"]),
            severity=str(row["severity"]),
            observed_at=utcnow(),
            evidence=dict(evidence or {}),
            detection_id=UUID(str(final["detection_id"])) if final.get("detection_id") else None,
            case_id=UUID(str(final["case_id"])) if final.get("case_id") else None,
            case_status=str(final.get("case_status") or "pending"),
        )


def _secret_for(kind: str) -> str:
    nonce = secrets.token_hex(16)
    # Every value is intentionally invalid/non-routable/non-authenticating.
    if kind == "fake_aws_key":
        return f"AKIA{nonce.upper()}"[:20]
    if kind == "fake_browser_cookie":
        return f"sentinel_canary={nonce}; Secure; HttpOnly"
    if kind == "fake_ssh_key":
        return f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{secrets.token_urlsafe(24)} sentinel-canary"
    if kind == "fake_wallet_seed":
        return "abandon " * 11 + "sentinel-canary"
    if kind == "fake_admin_share":
        return f"\\\\sentinel-canary.invalid\\share\\{nonce}"
    if kind == "fake_service_account":
        return f"sentinel-canary-{nonce}@invalid.local"
    return f"SENTINEL-CANARY-{nonce}"


def _honeyfile_content(artifact: DeceptionArtifact, metadata: Mapping[str, Any]) -> bytes:
    payload = {
        "document": "Sentinel Canary Document",
        "classification": "DECEPTION-CANARY",
        "warning": "This file contains inert Sentinel deception material. It is not a real credential.",
        "artifact_id": str(artifact.id),
        "callback": artifact.callback_url,
        "metadata": dict(metadata),
    }
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
