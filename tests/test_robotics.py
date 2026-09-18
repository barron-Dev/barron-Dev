from cyclothone.robotics.mcp_guard import MCPGuard
from cyclothone.robotics.sros2_audit import SROS2Auditor

def test_sros2_disabled_flagged(): assert any(f.kind=="no_sros2" for f in SROS2Auditor().audit({"sros2_enabled":False}).findings)
def test_keystore_world_readable(): assert any(f.kind=="keystore_world_readable" for f in SROS2Auditor().audit({"sros2_enabled":True,"keystore_path":"/keys","keystore_perms":"0777"}).findings)
def test_unauth_publisher_critical(): assert any(f.kind=="unauth_publisher" for f in SROS2Auditor().audit({"sros2_enabled":True,"topics":[{"name":"/cmd_vel","untrusted_publishers":2}]}).findings)
def test_mcp_flags_unsigned_server(): assert any(f["kind"]=="unsigned_mcp_server" for f in MCPGuard().audit_manifest({"mcp_servers":[{"name":"x","url":"https://x"}],"tools":[]})["findings"])
def test_mcp_tool_risk_scoring():
    r=MCPGuard().score_tool("dangerous",["shell_exec","file_write"]); assert r.score==1.0 and len(r.reasons)>=2
