from __future__ import annotations

import base64
import hashlib
import io
import json
import zipfile
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from cyclothone.compliance.signing import verify_digest_signature
from cyclothone.storage.supabase_client import supabase


class ComplianceVerificationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class VerificationResult:
    snapshot_id: str
    verified: bool
    pack_sha256: str
    manifest_sha256: str
    signer_kid: str | None
    checks: dict[str, bool]


class EvidencePackVerifier:
    """Verify a stored evidence pack against its immutable snapshot metadata."""

    async def verify(self, tenant_id: UUID, snapshot_id: UUID) -> VerificationResult:
        snapshot = await self._snapshot(tenant_id, snapshot_id)
        if not snapshot:
            raise ComplianceVerificationError("snapshot not found")

        pack_path = snapshot.get("pack_path")
        expected_pack_sha = str(snapshot.get("pack_sha256") or "")
        expected_manifest_sha = str(snapshot.get("manifest_sha256") or "")
        signature = str(snapshot.get("signature") or "")
        signer_kid = str(snapshot.get("signer_kid") or "") or None
        if not pack_path or not expected_pack_sha or not expected_manifest_sha or not signature:
            raise ComplianceVerificationError("snapshot is missing integrity metadata")

        pack = await self._download(str(pack_path))
        pack_sha_ok = hashlib.sha256(pack).hexdigest() == expected_pack_sha
        if not pack_sha_ok:
            return await self._record(tenant_id, snapshot_id, False, {"pack_sha256": False}, expected_pack_sha, expected_manifest_sha)

        try:
            files = self._read_zip(pack)
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            raise ComplianceVerificationError("stored evidence pack is not a valid ZIP") from exc

        manifest_raw = files.get("manifest.json")
        hashes_raw = files.get("file_hashes.json")
        if manifest_raw is None or hashes_raw is None:
            raise ComplianceVerificationError("pack is missing verification manifests")

        try:
            manifest = json.loads(manifest_raw.decode("utf-8"))
            file_hashes = json.loads(hashes_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ComplianceVerificationError("pack verification metadata is invalid") from exc

        signed_body = dict(manifest)
        signed_body.pop("manifest_sha256", None)
        signed_body.pop("signature", None)
        signed_body.pop("signer_kid", None)
        canonical = json.dumps(signed_body, sort_keys=True, separators=(",", ":"), default=str).encode()
        actual_manifest_sha = hashlib.sha256(canonical).hexdigest()
        manifest_sha_ok = actual_manifest_sha == expected_manifest_sha == str(manifest.get("manifest_sha256") or "")

        file_hashes_ok = True
        for name, expected in file_hashes.items():
            data = files.get(name)
            if data is None or hashlib.sha256(data).hexdigest() != str(expected):
                file_hashes_ok = False
                break

        signature_ok = False
        if manifest_sha_ok and signer_kid:
            try:
                signature_ok = await verify_digest_signature(expected_manifest_sha, signature, signer_kid)
            except Exception:  # noqa: BLE001
                signature_ok = False

        checks = {
            "pack_sha256": pack_sha_ok,
            "manifest_sha256": manifest_sha_ok,
            "file_hashes": file_hashes_ok,
            "signature": signature_ok,
        }
        verified = all(checks.values())
        await self._record(tenant_id, snapshot_id, verified, checks, expected_pack_sha, expected_manifest_sha)
        return VerificationResult(
            snapshot_id=str(snapshot_id),
            verified=verified,
            pack_sha256=expected_pack_sha,
            manifest_sha256=expected_manifest_sha,
            signer_kid=signer_kid,
            checks=checks,
        )

    @staticmethod
    def _read_zip(pack: bytes) -> dict[str, bytes]:
        with zipfile.ZipFile(io.BytesIO(pack), "r") as archive:
            if any(info.filename.startswith("/") or ".." in info.filename.split("/") for info in archive.infolist()):
                raise ValueError("unsafe ZIP path")
            return {info.filename: archive.read(info) for info in archive.infolist() if not info.is_dir()}

    async def _snapshot(self, tenant_id: UUID, snapshot_id: UUID) -> dict[str, Any] | None:
        async def _do():
            return await (await supabase._ensure()).table("compliance_evidence_snapshots").select(
                "id,pack_path,pack_sha256,manifest_sha256,signature,signer_kid"
            ).eq("id", str(snapshot_id)).eq("tenant_id", str(tenant_id)).limit(1).execute()

        rows = (await supabase._retry(_do, attempts=2)).data or []
        return rows[0] if rows else None

    async def _download(self, path: str) -> bytes:
        async def _do():
            return await (await supabase._ensure()).storage.from_("compliance").download(path)

        return await supabase._retry(_do, attempts=3)

    async def _record(
        self,
        tenant_id: UUID,
        snapshot_id: UUID,
        verified: bool,
        checks: dict[str, bool],
        pack_sha256: str,
        manifest_sha256: str,
    ) -> VerificationResult:
        async def _do():
            return await (await supabase._ensure()).table("compliance_snapshot_verifications").insert({
                "tenant_id": str(tenant_id),
                "snapshot_id": str(snapshot_id),
                "verified": verified,
                "pack_sha256": pack_sha256,
                "manifest_sha256": manifest_sha256,
                "checks": checks,
            }).execute()

        await supabase._retry(_do, attempts=2)
        return VerificationResult(
            snapshot_id=str(snapshot_id),
            verified=verified,
            pack_sha256=pack_sha256,
            manifest_sha256=manifest_sha256,
            signer_kid=None,
            checks=checks,
        )
