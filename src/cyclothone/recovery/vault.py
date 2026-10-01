from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import BinaryIO, Protocol


class ImmutableObjectStore(Protocol):
    """Production object-store contract.

    The implementation must use a bucket with Object Lock COMPLIANCE mode.
    A normal writable bucket MUST NOT be silently accepted as a vault.
    """

    def put_immutable(
        self,
        *,
        key: str,
        body: BinaryIO,
        content_length: int,
        sha256: str,
        retain_until: datetime,
        kms_key_ref: str,
    ) -> str: ...

    def verify_object(self, *, key: str, version_id: str, sha256: str) -> bool: ...


@dataclass(frozen=True)
class RecoveryVaultConfig:
    region: str
    bucket: str
    prefix: str
    kms_key_ref: str
    retention_days: int
    rpo_minutes: int = 15
    object_lock_mode: str = "COMPLIANCE"

    def validate(self) -> None:
        if not self.region or not self.bucket or not self.prefix:
            raise ValueError("recovery vault location is incomplete")
        if not self.kms_key_ref:
            raise ValueError("recovery vault KMS key reference is required")
        if self.object_lock_mode != "COMPLIANCE":
            raise ValueError("recovery vault requires Object Lock COMPLIANCE mode")
        if self.retention_days <= 0:
            raise ValueError("retention_days must be positive")
        if not 1 <= self.rpo_minutes <= 1440:
            raise ValueError("rpo_minutes must be between 1 and 1440")


class RecoveryVault:
    def __init__(self, config: RecoveryVaultConfig, store: ImmutableObjectStore) -> None:
        config.validate()
        self.config = config
        self.store = store

    def immutable_key(self, tenant_id: str, snapshot_id: str, relative_path: str) -> str:
        relative = relative_path.replace("\\", "/").lstrip("/")
        if ".." in relative.split("/"):
            raise ValueError("relative_path may not escape the tenant prefix")
        return f"{self.config.prefix.rstrip('/')}/{tenant_id}/{snapshot_id}/{relative}"

    def put(
        self,
        *,
        tenant_id: str,
        snapshot_id: str,
        relative_path: str,
        body: BinaryIO,
        content_length: int,
    ) -> tuple[str, str]:
        if content_length < 0:
            raise ValueError("content_length must be non-negative")
        key = self.immutable_key(tenant_id, snapshot_id, relative_path)
        digest = hashlib.sha256()
        # Hash the exact stream that is sent to the store. Callers that need
        # retries must provide a seekable stream or recreate it for each try.
        original_position = body.tell() if body.seekable() else None
        while chunk := body.read(1024 * 1024):
            digest.update(chunk)
        if original_position is not None:
            body.seek(original_position)
        sha256 = digest.hexdigest()
        retain_until = datetime.now(UTC) + timedelta(days=self.config.retention_days)
        version_id = self.store.put_immutable(
            key=key,
            body=body,
            content_length=content_length,
            sha256=sha256,
            retain_until=retain_until,
            kms_key_ref=self.config.kms_key_ref,
        )
        return key, version_id

    def verify(self, *, key: str, version_id: str, sha256: str) -> bool:
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256.lower()):
            raise ValueError("sha256 must be a hexadecimal SHA-256 digest")
        return self.store.verify_object(key=key, version_id=version_id, sha256=sha256)
