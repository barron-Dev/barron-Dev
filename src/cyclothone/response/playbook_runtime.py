from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from cyclothone.ai.envelope_issuer import EnvelopeIssueRequest
from cyclothone.response.orchestrator import ACTION_CLASS, ActionPlan, ActionStore, ResponseOrchestrator
from cyclothone.storage.supabase_client import supabase


class SupabaseActionStore(ActionStore):
    async def create(self, **values: Any) -> str:
        row = await supabase.insert_one("case_actions", values)
        case_id = values.get("case_id")
        if case_id:
            event = {
                "case_id": str(case_id),
                "actor": str(values.get("issued_by") or "response"),
                "kind": "response_action_created",
                "payload": {"case_action_id": str(row["id"]), "action": values.get("action"), "status": values.get("status")},
            }
            await supabase.insert_one("case_timeline", event)
            customer_link = await supabase.select_one("customer_case_links", "organization_id", case_id=str(case_id))
            if customer_link:
                await supabase.insert_one("customer_case_activity", {
                    "organization_id": customer_link["organization_id"],
                    "case_id": str(case_id),
                    "actor_user_id": None,
                    "actor_type": "system",
                    "event_type": "response_action_created",
                    "message": f"Response action {values.get('action') or 'action'} created.",
                    "metadata": event["payload"],
                })
        return str(row["id"])

    async def get(self, action_id: UUID) -> dict[str, Any] | None:
        return await supabase.select_one("case_actions", "*", id=str(action_id))

    async def update(self, action_id: UUID, **values: Any) -> None:
        current = await self.get(action_id)
        if not current:
            raise RuntimeError("case_action not found during update")
        updated = await supabase.update("case_actions", values, id=str(action_id))
        if updated is None:
            raise RuntimeError("case_action not found during update")
        if current.get("case_id"):
            actor = str(values.get("issued_by") or values.get("approved_by") or values.get("rejected_by") or "response")
            payload = {"case_action_id": str(action_id), "changes": values}
            await supabase.insert_one("case_timeline", {
                "case_id": str(current["case_id"]),
                "actor": actor,
                "kind": "response_action_updated",
                "payload": payload,
            })
            customer_link = await supabase.select_one("customer_case_links", "organization_id", case_id=str(current["case_id"]))
            if customer_link:
                await supabase.insert_one("customer_case_activity", {
                    "organization_id": customer_link["organization_id"],
                    "case_id": str(current["case_id"]),
                    "actor_user_id": None,
                    "actor_type": "system",
                    "event_type": "response_action_updated",
                    "message": "A response action changed state.",
                    "metadata": payload,
                })

    async def blast_allowed(
        self, rule_id: UUID, limit: int, window_minutes: int = 60,
        tenant_id: UUID | None = None, device_id: UUID | None = None,
    ) -> bool:
        if tenant_id is None or device_id is None:
            return False
        rows = await supabase.rpc("check_blast_radius_scoped", {
            "p_rule_id": str(rule_id),
            "p_tenant_id": str(tenant_id),
            "p_device_id": str(device_id),
            "p_limit": int(limit),
            "p_window_minutes": int(window_minutes),
        })
        return bool(rows)

    async def record_blast(self, *, rule_id: UUID, tenant_id: UUID, device_id: UUID, case_id: UUID) -> None:
        await supabase.insert_one("rule_blast_log", {
            "rule_id": str(rule_id),
            "tenant_id": str(tenant_id),
            "device_id": str(device_id),
            "case_id": str(case_id),
        })


class PlaybookValidationError(ValueError):
    pass


def compile_playbook_steps(raw_steps: Any) -> list[ActionPlan]:
    if not isinstance(raw_steps, list):
        raise PlaybookValidationError("playbook steps must be an array")
    if not raw_steps:
        raise PlaybookValidationError("playbook must contain at least one step")
    if len(raw_steps) > 50:
        raise PlaybookValidationError("playbook cannot contain more than 50 steps")

    compiled: list[ActionPlan] = []
    for index, raw in enumerate(raw_steps):
        if not isinstance(raw, dict):
            raise PlaybookValidationError(f"step {index} must be an object")
        action = str(raw.get("action") or "").strip()
        if action not in ACTION_CLASS:
            raise PlaybookValidationError(f"step {index} uses unsupported action '{action}'")
        args = raw.get("args") or {}
        if not isinstance(args, dict):
            raise PlaybookValidationError(f"step {index} args must be an object")
        rollback = raw.get("rollback")
        if rollback is not None and not isinstance(rollback, dict):
            raise PlaybookValidationError(f"step {index} rollback must be an object")
        cls = ACTION_CLASS[action]
        requires = bool(raw.get("requires_approval")) or cls.value in ("high", "critical")

        model_id = raw.get("model_id")
        provider_id = raw.get("provider_id")
        target = raw.get("target")
        agent_id = raw.get("agent_id")
        mission_id = raw.get("mission_id")
        mission_version = raw.get("mission_version")
        mission_hash = raw.get("mission_hash")
        run_id = raw.get("ai_run_id")

        if cls.value in ("medium", "high", "critical"):
            required = {
                "model_id": model_id,
                "provider_id": provider_id,
                "target": target,
                "agent_id": agent_id,
                "mission_id": mission_id,
                "mission_version": mission_version,
                "mission_hash": mission_hash,
                "ai_run_id": run_id,
            }
            missing = [key for key, value in required.items() if value in (None, "")]
            if missing:
                raise PlaybookValidationError(
                    f"step {index} destructive response is missing canonical execution binding: {', '.join(missing)}"
                )
            try:
                agent_uuid = UUID(str(agent_id))
                run_uuid = UUID(str(run_id))
                mission_ver = int(mission_version)
            except (TypeError, ValueError) as exc:
                raise PlaybookValidationError(
                    f"step {index} has invalid canonical execution binding"
                ) from exc
            if len(str(mission_hash)) != 64:
                raise PlaybookValidationError(f"step {index} mission_hash must be SHA-256")
            envelope_request = EnvelopeIssueRequest(
                tenant_id=UUID("00000000-0000-0000-0000-000000000000"),
                agent_id=agent_uuid,
                model_id=str(model_id),
                provider_id=str(provider_id),
                tool_name=action,
                action=action,
                args=args,
                target=str(target),
                mission_id=str(mission_id),
                mission_version=mission_ver,
                mission_hash=str(mission_hash),
            )
        else:
            run_uuid = None
            envelope_request = None

        compiled.append(ActionPlan(
            action=action,
            args=args,
            requires_approval=requires,
            rollback=rollback,
            envelope_request=envelope_request,
            model_id=str(model_id) if model_id is not None else None,
            provider_id=str(provider_id) if provider_id is not None else None,
            target=str(target) if target is not None else None,
            mission_id=str(mission_id) if mission_id is not None else None,
            mission_version=int(mission_version) if mission_version is not None else None,
            mission_hash=str(mission_hash) if mission_hash is not None else None,
            run_id=run_uuid,
        ))
    return compiled


class PlaybookRunner:
    def __init__(self, orchestrator: ResponseOrchestrator, store: SupabaseActionStore | None = None) -> None:
        self.orchestrator = orchestrator
        self.store = store or SupabaseActionStore()

    async def run(
        self,
        *,
        tenant_id: UUID,
        playbook_id: UUID,
        case_id: UUID,
        device_id: UUID | None,
        issued_by: str,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        playbook = await supabase.select_one(
            "playbooks", "id,tenant_id,name,enabled,steps",
            id=str(playbook_id), tenant_id=str(tenant_id),
        )
        if not playbook:
            raise PlaybookValidationError("playbook not found")
        if not playbook.get("enabled"):
            raise PlaybookValidationError("playbook is disabled")

        steps = compile_playbook_steps(playbook.get("steps"))
        run = await supabase.insert_one("playbook_runs", {
            "tenant_id": str(tenant_id),
            "playbook_id": str(playbook_id),
            "case_id": str(case_id),
            "device_id": str(device_id) if device_id else None,
            "status": "running",
            "current_step": 0,
            "log": [],
        })
        run_id = UUID(str(run["id"]))

        log: list[dict[str, Any]] = []
        try:
            result = await self.orchestrator.run_chain(
                tenant_id=tenant_id,
                case_id=case_id,
                device_id=device_id,
                plan=steps,
                issued_by=issued_by,
                initiated_by_rule=None,
                dry_run=dry_run,
            )
            for i, action_id in enumerate(result.dispatched + result.queued + result.rejected):
                log.append({"action_id": action_id, "position": i})
            status = "completed" if not result.rejected else ("awaiting_approval" if result.queued and not result.rejected else "failed")
            await supabase.update("playbook_runs", {
                "status": status,
                "current_step": len(steps),
                "log": log,
                "ended_at": datetime.now(UTC).isoformat() if status in ("completed", "failed") else None,
            }, id=str(run_id), tenant_id=str(tenant_id))
            return {
                "run_id": str(run_id),
                "playbook_id": str(playbook_id),
                "case_id": str(case_id),
                "status": status,
                "dispatched": result.dispatched,
                "queued": result.queued,
                "rejected": result.rejected,
                "reasons": result.reasons,
            }
        except Exception as exc:
            await supabase.update("playbook_runs", {
                "status": "failed",
                "current_step": 0,
                "log": [{"error": str(exc)[:500]}],
                "ended_at": datetime.now(UTC).isoformat(),
            }, id=str(run_id), tenant_id=str(tenant_id))
            raise
