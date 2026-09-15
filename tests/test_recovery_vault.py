from datetime import UTC, datetime
from io import BytesIO

import pytest

from sentinel.recovery.restore import RecoveryRestore
from sentinel.recovery.vault import RecoveryVault, RecoveryVaultConfig


class Store:
    def __init__(self):
        self.items = {}

    def put_immutable(self, *, key, body, content_length, sha256, retain_until, kms_key_ref):
        self.items[key] = (sha256, content_length, retain_until, kms_key_ref)
        return "version-1"

    def verify_object(self, *, key, version_id, sha256):
        return key in self.items and self.items[key][0] == sha256 and version_id == "version-1"


def test_vault_requires_compliance_mode():
    with pytest.raises(ValueError):
        RecoveryVaultConfig("ae-1", "bucket", "vault", "kms://tenant", 30, object_lock_mode="GOVERNANCE").validate()


def test_put_hashes_exact_bytes_and_uses_retention():
    store = Store()
    vault = RecoveryVault(RecoveryVaultConfig("ae-1", "bucket", "vault", "kms://tenant", 30), store)
    key, version = vault.put(
        tenant_id="tenant",
        snapshot_id="snapshot",
        relative_path="server/file.txt",
        body=BytesIO(b"sentinel"),
        content_length=8,
    )
    assert version == "version-1"
    assert key.endswith("/tenant/snapshot/server/file.txt")
    assert vault.verify(key=key, version_id=version, sha256=store.items[key][0])
    assert store.items[key][2] > datetime.now(UTC)


def test_restore_refuses_unverified_object():
    store = Store()
    vault = RecoveryVault(RecoveryVaultConfig("ae-1", "bucket", "vault", "kms://tenant", 30), store)
    restore = RecoveryRestore(vault)
    with pytest.raises(RuntimeError):
        restore.restore(
            [{"object_key": "missing", "version_id": "v1", "sha256": "0" * 64, "size_bytes": 1}],
            lambda _: None,
        )
