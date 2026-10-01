from __future__ import annotations

from datetime import datetime
from typing import BinaryIO

try:
    import boto3
except ImportError as exc:  # pragma: no cover - deployment dependency guard
    boto3 = None
    _BOTO3_IMPORT_ERROR = exc
else:
    _BOTO3_IMPORT_ERROR = None


class S3ObjectLockStore:
    """S3-compatible immutable store backed by Object Lock.

    The bucket is expected to be pre-created with Object Lock enabled.
    This class deliberately fails closed when that configuration cannot be
    verified; it never downgrades to an ordinary writable object.
    """

    def __init__(self, *, bucket: str, client=None) -> None:
        if boto3 is None:
            raise RuntimeError("boto3 is required for the Recovery Vault S3 backend") from _BOTO3_IMPORT_ERROR
        self.bucket = bucket
        self.client = client or boto3.client("s3")
        self._assert_object_lock_enabled()

    def _assert_object_lock_enabled(self) -> None:
        try:
            status = self.client.get_object_lock_configuration(Bucket=self.bucket)
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError("unable to verify S3 Object Lock configuration") from exc
        mode = ((status.get("ObjectLockConfiguration") or {}).get("ObjectLockEnabled"))
        if mode != "Enabled":
            raise RuntimeError("Recovery Vault bucket must have S3 Object Lock enabled")

    def put_immutable(
        self,
        *,
        key: str,
        body: BinaryIO,
        content_length: int,
        sha256: str,
        retain_until: datetime,
        kms_key_ref: str,
    ) -> str:
        response = self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=body,
            ContentLength=content_length,
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=kms_key_ref,
            ChecksumSHA256=_sha256_base64(sha256),
            ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=retain_until,
            Metadata={"sha256": sha256},
        )
        return str(response.get("VersionId") or "")

    def verify_object(self, *, key: str, version_id: str, sha256: str) -> bool:
        response = self.client.head_object(Bucket=self.bucket, Key=key, VersionId=version_id)
        metadata = response.get("Metadata") or {}
        return metadata.get("sha256", "").lower() == sha256.lower()


def _sha256_base64(hex_digest: str) -> str:
    import base64
    return base64.b64encode(bytes.fromhex(hex_digest)).decode("ascii")
