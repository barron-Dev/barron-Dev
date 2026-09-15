from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from sentinel.recovery.vault import RecoveryVault


@dataclass(frozen=True)
class RestoreResult:
    restored_objects: int
    restored_bytes: int
    verified: bool


class RecoveryRestore:
    """Restore only from a verified immutable snapshot.

    The destination callback is responsible for writing to a clean host.
    This layer deliberately refuses to restore an object until its recorded
    SHA-256 has been verified against the immutable object version.
    """

    def __init__(self, vault: RecoveryVault) -> None:
        self.vault = vault

    def restore(
        self,
        objects: Iterable[dict],
        destination: Callable[[dict], None],
    ) -> RestoreResult:
        count = 0
        total = 0
        for obj in objects:
            key = str(obj["object_key"])
            version_id = str(obj["version_id"])
            digest = str(obj["sha256"])
            if not self.vault.verify(key=key, version_id=version_id, sha256=digest):
                raise RuntimeError(f"immutable object verification failed: {key}")
            destination(obj)
            count += 1
            total += int(obj["size_bytes"])
        return RestoreResult(restored_objects=count, restored_bytes=total, verified=True)
