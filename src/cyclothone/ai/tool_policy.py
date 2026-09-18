from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from cyclothone.ai.injection import PromptInjectionDetector
from cyclothone.storage.supabase_client import supabase

class ToolPolicyEngine:
    """Fail-closed tool authorization for tenant-owned agents."""
    def __init__(self)->None: self.injection=PromptInjectionDetector()

    async def check(self,tenant_id:UUID,agent_id:UUID,tool_name:str,args:dict[str,Any])->dict[str,Any]:
        if not await self._agent_owned(tenant_id,agent_id): return {"allowed":False,"reason":"agent_not_owned_by_tenant","score":1.0}
        policy=await self._load_policy(agent_id,tool_name)
        if policy is None:return {"allowed":False,"reason":"tool_not_declared","score":.9}
        if not policy.get("allowed",True):return {"allowed":False,"reason":"tool_denied_by_policy","score":1.0}
        for key,rule in (policy.get("arg_constraints") or {}).items():
            if not self._check_constraint(args.get(key),rule): return {"allowed":False,"reason":f"arg_constraint_violation:{key}","score":.8}
        verdict=self.injection.check_tool_call(tool_name,args)
        if verdict.verdict=="malicious":return {"allowed":False,"reason":"malicious_tool_args","score":verdict.score,"signals":verdict.signals}
        count=await self._recent_count(agent_id,tool_name)
        if count>=int(policy.get("max_calls_per_minute",60)):return {"allowed":False,"reason":"rate_limited","score":.5}
        approval=bool(policy.get("requires_approval"))
        return {"allowed":not approval,"requires_approval":approval,"reason":"pending_approval" if approval else "ok","score":verdict.score}

    async def _agent_owned(self,tenant_id:UUID,agent_id:UUID)->bool:
        row=await supabase.select_one("ai_agents","id",id=str(agent_id),tenant_id=str(tenant_id),status="active")
        return bool(row)

    async def _load_policy(self,agent_id:UUID,tool_name:str)->dict[str,Any]|None:
        async def do():
            client=await supabase._ensure()
            return await client.table("agent_tool_policy").select("*").eq("agent_id",str(agent_id)).eq("tool_name",tool_name).limit(1).execute()
        resp=await supabase._retry(do)
        rows=resp.data or []
        return rows[0] if rows else None

    async def _recent_count(self,agent_id:UUID,tool_name:str)->int:
        since=(datetime.now(UTC)-timedelta(minutes=1)).isoformat()
        async def do():
            client=await supabase._ensure()
            return await client.table("agent_actions").select("id",count="exact").eq("agent_id",str(agent_id)).eq("tool_name",tool_name).eq("kind","tool_call").gte("ts",since).execute()
        resp=await supabase._retry(do)
        return int(resp.count or len(resp.data or []))

    @staticmethod
    def _check_constraint(value:Any,rule:dict[str,Any])->bool:
        if value is None:return True
        if "prefix" in rule:return isinstance(value,str) and value.startswith(str(rule["prefix"]))
        if "suffix" in rule:return isinstance(value,str) and value.endswith(str(rule["suffix"]))
        if "one_of" in rule:return value in rule["one_of"]
        if "max_length" in rule:return isinstance(value,str) and len(value)<=int(rule["max_length"])
        return False
