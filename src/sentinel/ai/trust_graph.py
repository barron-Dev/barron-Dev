from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sentinel.storage.supabase_client import supabase

class AgentTrustGraph:
    HIGH_FREQUENCY=100

    async def record_call(self,tenant_id:UUID,source_agent:UUID,target_agent:UUID)->dict:
        if source_agent==target_agent: raise ValueError("source and target agents must differ")
        agents=await self._owned_agents(tenant_id,source_agent,target_agent)
        if len(agents)!=2: raise PermissionError("agent pair is not owned by tenant")
        now=datetime.now(UTC); now_s=now.isoformat()
        async def load():
            client=await supabase._ensure()
            return await client.table("agent_trust").select("*").eq("tenant_id",str(tenant_id)).eq("source_agent_id",str(source_agent)).eq("target_agent_id",str(target_agent)).limit(1).execute()
        resp=await supabase._retry(load); rows=resp.data or []
        if rows:
            row=rows[0]; count=int(row["call_count"])+1
            first=datetime.fromisoformat(str(row["first_seen"]).replace("Z","+00:00"))
            minutes=max(1,(now-first).total_seconds()/60); risk=min(count/minutes/self.HIGH_FREQUENCY,1.0)
            async def update():
                client=await supabase._ensure()
                return await client.table("agent_trust").update({"call_count":count,"last_seen":now_s,"risk_score":risk}).eq("tenant_id",str(tenant_id)).eq("source_agent_id",str(source_agent)).eq("target_agent_id",str(target_agent)).execute()
            await supabase._retry(update)
            return {"new_edge":False,"call_count":count,"risk":risk}
        async def insert():
            client=await supabase._ensure()
            return await client.table("agent_trust").insert({"tenant_id":str(tenant_id),"source_agent_id":str(source_agent),"target_agent_id":str(target_agent),"call_count":1,"first_seen":now_s,"last_seen":now_s,"risk_score":.4}).execute()
        await supabase._retry(insert)
        return {"new_edge":True,"call_count":1,"risk":.4}

    async def _owned_agents(self,tenant_id:UUID,*ids:UUID)->list[dict]:
        found=[]
        for agent_id in ids:
            row=await supabase.select_one("ai_agents","id,status",id=str(agent_id),tenant_id=str(tenant_id))
            if row: found.append(row)
        return found
