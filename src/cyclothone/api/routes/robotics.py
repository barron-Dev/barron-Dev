from __future__ import annotations
class SROS2AuditRequest(BaseModel):
    fleet_id:UUID
    robot_serial:str=Field(max_length=120)
    inventory:dict

async def _robot_id(tenant_id:UUID,fleet_id:UUID,serial:str):
    async def load():
        c=await supabase._ensure()
        return await c.table("robot_devices").select("id").eq("tenant_id",str(tenant_id)).eq("fleet_id",str(fleet_id)).eq("serial",serial).limit(1).execute()
    rows=list((await supabase._retry(load)).data or [])
    return rows[0]["id"] if rows else None

@router.post("/sros2/audit")
async def audit_sros2(body:SROS2AuditRequest,principal:Principal=Depends(require_role("owner","admin","member"))):
    robot_id=await _robot_id(principal.tenant_id,body.fleet_id,body.robot_serial)
    if not robot_id: raise HTTPException(404,"robot device not found")
    result=SROS2Auditor().audit(body.inventory)
    for f in result.findings:
        if f.severity in ("critical","high"):
            async def save(f=f):
                c=await supabase._ensure()
                return await c.table("robot_anomalies").insert({"tenant_id":str(principal.tenant_id),"robot_id":robot_id,
                    "kind":f.kind if f.kind in {"unauth_publisher","topic_hijack","msg_spoof","keystore_access","unexpected_topic","frequency_anomaly","firmware_downgrade","rogue_node","command_injection"} else "unexpected_topic",
                    "severity":f.severity,"evidence":f.evidence}).execute()
            try: await supabase._retry(save,attempts=1)
            except Exception: pass
    return {"findings":[{"kind":f.kind,"severity":f.severity,"detail":f.detail,"evidence":f.evidence} for f in result.findings],
            "fingerprint":SROS2Auditor.fingerprint(body.inventory),"count":len(result.findings)}

class MCPAuditRequest(BaseModel):
    agent_id:str=Field(max_length=120)
    manifest:dict

@router.post("/mcp/audit")
async def audit_mcp(body:MCPAuditRequest,principal:Principal=Depends(require_role("owner","admin","member"))):
    result=MCPGuard().audit_manifest(body.manifest)
    async def save():
        c=await supabase._ensure()
        return await c.table("ai_agent_manifests").upsert({"tenant_id":str(principal.tenant_id),"agent_id":body.agent_id,
            "framework":body.manifest.get("framework","unknown"),"model":body.manifest.get("model","unknown"),
            "tools":body.manifest.get("tools",[]),"mcp_servers":body.manifest.get("mcp_servers",[]),
            "signed":all(s.get("signature") for s in body.manifest.get("mcp_servers",[])),"manifest_hash":result["fingerprint"]},
            on_conflict="tenant_id,agent_id,manifest_hash").execute()
    try: await supabase._retry(save,attempts=2)
    except Exception: pass
    return result

@router.get("/fleets")
async def list_fleets(principal:Principal=Depends(get_principal)):
    async def load():
        c=await supabase._ensure()
        return await c.table("robot_fleets").select("*").eq("tenant_id",str(principal.tenant_id)).order("created_at",desc=True).execute()
    return list((await supabase._retry(load)).data or [])

@router.get("/anomalies")
async def list_anomalies(status_filter:str|None=None,limit:int=Query(default=200,ge=1,le=1000),
                         principal:Principal=Depends(get_principal)):
    async def load():
        c=await supabase._ensure()
        q=c.table("robot_anomalies").select("*").eq("tenant_id",str(principal.tenant_id)).order("first_seen",desc=True).limit(limit)
        if status_filter: q=q.eq("status",status_filter)
        return await q.execute()
    return list((await supabase._retry(load)).data or [])
