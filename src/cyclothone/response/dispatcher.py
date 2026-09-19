from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from typing import Any
from uuid import UUID, uuid4

from cyclothone.compliance.signing import sign_digest
from cyclothone.response.orchestrator import ACTION_CLASS
from cyclothone.storage.supabase_client import supabase

_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_ALLOWED_ACTIONS = frozenset(ACTION_CLASS) | {"unblock_hash", "unblock_ip"}
_MAX_TTL = 900


class CommandDispatchError(RuntimeError):
    pass


def canonical_command_payload(*, command_id: UUID, tenant_id: UUID, device_id: UUID, action: str,
                              args: dict[str, Any], issued_by: str, issued_at: datetime,
                              expires_at: datetime, case_action_id: UUID | None = None,
                              execution_context: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "id": str(command_id),
        "tenant_id": str(tenant_id),
        "device_id": str(device_id),
        "action": action,
        "args": args,
        "issued_by": issued_by,
        "issued_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "case_action_id": str(case_action_id) if case_action_id else None,
        "execution_context": execution_context or {},
    }


def command_digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_args(action: str, args: dict[str, Any]) -> None:
    if not isinstance(args, dict):
        raise CommandDispatchError("command args must be an object")
    if action == "kill_process":
        pid = args.get("pid")
        if not isinstance(pid, int) or pid <= 0:
            raise CommandDispatchError("kill_process requires a positive pid")
    elif action in {"block_hash", "unblock_hash"}:
        value = args.get("sha256")
        if not isinstance(value, str) or not _SHA256.fullmatch(value):
            raise CommandDispatchError(f"{action} requires a SHA-256 digest")
    elif action in {"block_ip", "unblock_ip"}:
        value = args.get("ip")
        if not isinstance(value, str):
            raise CommandDispatchError(f"{action} requires an IP address")
        try:
            ip_address(value)
        except ValueError as exc:
            raise CommandDispatchError("invalid IP address") from exc
    elif action in {"quarantine_file", "restore_file"}:
        key = "path" if action == "quarantine_file" else "original"
        value = args.get(key)
        if not isinstance(value, str) or not value.strip() or len(value) > 4096:
            raise CommandDispatchError(f"{action} requires a valid file path")
    elif action == "disable_account":
        account = args.get("account")
        if not isinstance(account, str) or not account.strip() or len(account) > 320:
            raise CommandDispatchError("disable_account requires an account identifier")


class SupabaseCommandDispatcher:
    async def issue(self, *, tenant_id: UUID, device_id: UUID | None, action: str,
                    args: dict[str, Any], issued_by: str, case_action_id: UUID | None = None,
                    execution_context: dict[str, Any] | None = None) -> dict[str, Any]:
        if device_id is None:
            raise CommandDispatchError("device_id is required for agent commands")
        if action not in _ALLOWED_ACTIONS:
            raise CommandDispatchError(f"action '{action}' is not allowlisted")
        _validate_args(action, args)

        client = await supabase._ensure()
        response = await (
            client.table("devices")
            .select("id,tenant_id,status,cert_fingerprint,certificate_not_before,certificate_not_after")
            .eq("id", str(device_id))
            .eq("tenant_id", str(tenant_id))
            .limit(1)
            .execute()
        )
        devices = response.data or []
        if not devices or devices[0].get("status") != "active":
            raise CommandDispatchError("target device is not active")
        if not devices[0].get("cert_fingerprint"):
            raise CommandDispatchError("target device has no mTLS identity")
        if devices[0].get("status") == "retired":
            raise CommandDispatchError("target device is retired")

        ttl = min(max(int(os.getenv("CYCLOTHONE_COMMAND_TTL_SECONDS", "300")), 30), _MAX_TTL)
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=ttl)
        command_id = uuid4()
        payload = canonical_command_payload(
            command_id=command_id, tenant_id=tenant_id, device_id=device_id,
            action=action, args=args, issued_by=issued_by[:256],
            issued_at=now, expires_at=expires_at,
            case_action_id=case_action_id, execution_context=execution_context,
        )
        signature = await sign_digest(command_digest(payload))

        await supabase.insert_one("commands", {
            "id": str(command_id), "tenant_id": str(tenant_id), "device_id": str(device_id),
            "action": action, "args": args, "signature": signature.signature_b64,
            "signer_kid": signature.kid, "status": "pending", "issued_by": issued_by[:256],
            "issued_at": now.isoformat(), "expires_at": expires_at.isoformat(),
            "case_action_id": str(case_action_id) if case_action_id else None,
            "ai_run_id": (execution_context or {}).get("run_id"),
            "ai_agent_id": (execution_context or {}).get("agent_id"),
            "ai_model_id": (execution_context or {}).get("model_id"),
            "ai_provider_id": (execution_context or {}).get("provider_id"),
            "ai_tool_name": (execution_context or {}).get("tool_name"),
            "ai_target": (execution_context or {}).get("target"),
            "ai_envelope_id": (execution_context or {}).get("envelope_id"),
            "ai_envelope_hash": (execution_context or {}).get("envelope_hash"),
            "ai_args_hash": (execution_context or {}).get("args_hash"),
            "ai_mission_id": (execution_context or {}).get("mission_id"),
            "ai_mission_version": (execution_context or {}).get("mission_version"),
            "ai_mission_hash": (execution_context or {}).get("mission_hash"),
        })
        return {"id": str(command_id), "status": "pending",
                "signer_kid": signature.kid, "expires_at": expires_at.isoformat()}
