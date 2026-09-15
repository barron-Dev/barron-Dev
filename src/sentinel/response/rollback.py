from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol
from uuid import UUID

from .orchestrator import Dispatcher


class RollbackError(Exception):
    """Base error for rollback validation or execution failures."""


class RollbackConflict(RollbackError):
    """The case action is not currently eligible for rollback."""


class ActionStore(Protocol):
    async def get(self, action_id: UUID) -> dict[str, Any] | None: ...
    async def update(self, action_id: UUID, **values: Any) -> None: ...


@dataclass(frozen=True, slots=True)
class InverseAction:
    action: str
    args: dict[str, Any]


def _invert_kill_process(args: dict[str, Any]) -> InverseAction | None:
    return None


def _invert_quarantine_file(args: dict[str, Any]) -> InverseAction | None:
    path = args.get("path")
    return InverseAction("restore_file", {"original": path}) if isinstance(path, str) and path else None


def _invert_restore_file(args: dict[str, Any]) -> InverseAction | None:
    path = args.get("original")
    return InverseAction("quarantine_file", {"path": path}) if isinstance(path, str) and path else None


def _invert_block_hash(args: dict[str, Any]) -> InverseAction | None:
    sha = args.get("sha256")
    return InverseAction("unblock_hash", {"sha256": sha}) if isinstance(sha, str) and sha else None


def _invert_block_ip(args: dict[str, Any]) -> InverseAction | None:
    ip = args.get("ip")
    return InverseAction("unblock_ip", {"ip": ip}) if isinstance(ip, str) and ip else None


def _invert_isolate_host(args: dict[str, Any]) -> InverseAction:
    return InverseAction("release_host", {})


def _invert_release_host(args: dict[str, Any]) -> InverseAction:
    return InverseAction("isolate_host", {})


INVERSE_MAP = {
    "kill_process": _invert_kill_process,
    "quarantine_file": _invert_quarantine_file,
    "restore_file": _invert_restore_file,
    "block_hash": _invert_block_hash,
    "block_ip": _invert_block_ip,
    "isolate_host": _invert_isolate_host,
    "release_host": _invert_release_host,
}


class RollbackService:
    """Create an explicitly defined inverse command for a successful action.

    The dispatcher is intentionally responsible only for issuing the inverse
    command. Persistence is supplied through ActionStore so the same domain
    service can be used by the API layer and tested without a fake network or
    agent. A case action is marked rolled_back only after the dispatcher
    confirms the inverse command itself completed successfully.
    """

    def __init__(self, dispatcher: Dispatcher, store: ActionStore) -> None:
        self.dispatcher = dispatcher
        self.store = store

    async def rollback(self, *, tenant_id: UUID, case_action_id: UUID, actor: str) -> dict[str, Any]:
        row = await self.store.get(case_action_id)
        if not row or str(row.get("tenant_id")) != str(tenant_id):
            raise RollbackConflict("case_action not found")

        if row.get("status") != "success":
            raise RollbackConflict(
                f"case_action is {row.get('status')}; only success can be rolled back"
            )
        if row.get("rolled_back_at"):
            raise RollbackConflict("case_action is already rolled back")

        builder = INVERSE_MAP.get(str(row.get("action")))
        if builder is None:
            raise RollbackError(f"action '{row.get('action')}' has no defined inverse")

        inverse = builder(row.get("args") or {})
        if inverse is None:
            raise RollbackError(
                f"cannot build inverse for '{row.get('action')}' with given args"
            )

        raw_device_id = row.get("device_id")
        if not raw_device_id:
            raise RollbackError("case_action has no device_id")
        device_id = UUID(str(raw_device_id))

        command = await self.dispatcher.issue(
            tenant_id=tenant_id,
            device_id=device_id,
            action=inverse.action,
            args=inverse.args,
            issued_by=f"rollback:{actor}",
        )

        # A dispatcher must report terminal success before the source action
        # becomes rolled_back. Queued/executing commands are not enough.
        if str(command.get("status", "")).lower() != "success":
            error = str(command.get("error") or "inverse command did not complete successfully")[:500]
            await self.store.update(
                case_action_id,
                rollback_command_id=command.get("id"),
                rollback_error=error,
            )
            raise RollbackError(error)

        now = datetime.now(timezone.utc).isoformat()
        await self.store.update(
            case_action_id,
            status="rolled_back",
            rolled_back_at=now,
            rollback_command_id=command["id"],
            rollback_error=None,
        )

        return {
            "case_action_id": str(case_action_id),
            "inverse_action": inverse.action,
            "inverse_args": inverse.args,
            "rollback_command_id": command["id"],
        }
