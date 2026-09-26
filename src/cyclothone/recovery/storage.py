from __future__ import annotations

import asyncio
import hashlib
import os
from dataclasses import dataclass
from typing import BinaryIO

import boto3
from botocore.config import Config


@dataclass(frozen=True)
class RecoveryObject:
    key: str
    sha256: str
    size: int
    content_type: str


class RecoveryStorage:
    """Real S3-compatible Recovery storage adapter.

    This adapter never fabricates Recovery records. It only performs storage
    operations against the configured production bucket.
    """

    def __init__(self) -> None:
        self.bucket = os.getenv("CYCLOTHONE_RECOVERY_BUCKET")
        self.region = os.getenv("CYCLOTHONE_RECOVERY_REGION")
        self.endpoint = os.getenv("CYCLOTHONE_RECOVERY_ENDPOINT")
        self.access_key = os.getenv("CYCLOTHONE_RECOVERY_ACCESS_KEY_ID")
        self.secret_key = os.getenv("CYCLOTHONE_RECOVERY_SECRET_ACCESS_KEY")

    def configured(self) -> bool:
        return all((self.bucket, self.region, self.endpoint, self.access_key, self.secret_key))

    def _client(self):
        if not self.configured():
            raise RuntimeError("Recovery object storage is not fully configured")
        return boto3.client(
            "s3",
            region_name=self.region,
            endpoint_url=self.endpoint,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            config=Config(signature_version="s3v4"),
        )

    async def verify_access(self) -> dict[str, str | bool]:
        client = self._client()

        def check() -> None:
            client.head_bucket(Bucket=self.bucket)

        await asyncio.to_thread(check)
        return {"configured": True, "reachable": True, "bucket": self.bucket}

    async def put_stream(
        self,
        key: str,
        stream: BinaryIO,
        *,
        content_type: str = "application/octet-stream",
    ) -> RecoveryObject:
        client = self._client()
        digest = hashlib.sha256()
        size = 0

        while True:
            chunk = await asyncio.to_thread(stream.read, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)

        stream.seek(0)
        checksum = digest.hexdigest()

        def upload() -> None:
            client.upload_fileobj(
                stream,
                self.bucket,
                key,
                ExtraArgs={"ContentType": content_type},
            )

        await asyncio.to_thread(upload)
        return RecoveryObject(key=key, sha256=checksum, size=size, content_type=content_type)

    async def get(self, key: str) -> bytes:
        client = self._client()

        def download() -> bytes:
            response = client.get_object(Bucket=self.bucket, Key=key)
            return response["Body"].read()

        return await asyncio.to_thread(download)

    async def delete(self, key: str) -> None:
        client = self._client()
        await asyncio.to_thread(client.delete_object, Bucket=self.bucket, Key=key)


recovery_storage = RecoveryStorage()
