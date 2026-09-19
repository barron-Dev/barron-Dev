from __future__ import annotations
import hashlib,json
from dataclasses import dataclass
TOOL_RISK={"file_read":.3,"file_write":.6,"file_delete":.9,"shell_exec":1.0,"code_eval":1.0,"http_get":.2,"http_post":.4,"db_query":.4,"db_write":.7,"db_drop":1.0,"email_send":.5,"sms_send":.5,"payment":1.0,"browser_navigate":.3,"browser_click":.4,"memory_write":.6,"memory_read":.2,"agent_message":.5}
@dataclass
class ToolRisk: name:str; score:float; capabilities:list[str]; reasons:list[str]
class MCPGuard:
    def audit_manifest(self,manifest):
        findings=[]
        for s in manifest.get("mcp_servers",[]):
            if not s.get("signature"): findings.append({"kind":"unsigned_mcp_server","severity":"critical","detail":f"MCP server '{s.get('name')}' has no signature.","evidence":{"server":s.get("name")}})
        for t in manifest.get("tools",[]):
            if not t.get("schema"): findings.append({"kind":"schema_less_tool","severity":"high","detail":f"Tool '{t.get('name')}' has no input schema.","evidence":{"tool":t.get("name")}})
            for cap in t.get("capabilities") or []:
                if TOOL_RISK.get(cap,0)>=.9 and not t.get("approved"): findings.append({"kind":"unapproved_dangerous_tool","severity":"critical","detail":f"Tool '{t.get('name')}' has capability '{cap}' without approval.","evidence":{"tool":t.get("name"),"capability":cap}})
        for s in manifest.get("mcp_servers",[]):
            u=s.get("url","")
            if u and not u.startswith(("https://","http://127.0.0.1","http://localhost")): findings.append({"kind":"insecure_mcp_transport","severity":"high","detail":f"MCP server '{s.get('name')}' uses insecure transport.","evidence":{"url":u}})
        return {"findings":findings,"fingerprint":self._fingerprint(manifest)}
    def score_tool(self,name,capabilities):
        reasons=[]; score=0
        for cap in capabilities:
            w=TOOL_RISK.get(cap,.3); score+=w
            if w>=.8: reasons.append(f"high-impact capability: {cap}")
            elif w>=.5: reasons.append(f"privileged capability: {cap}")
        return ToolRisk(name,min(score,1),capabilities,reasons)
    @staticmethod
    def _fingerprint(manifest): return hashlib.sha256(json.dumps(manifest,sort_keys=True,default=str).encode()).hexdigest()
