import pytest
from cyclothone.ai.mission import MissionCompiler, MissionCompileError

def base():
    return {"mission_id":"m1","version":1,"nodes":[{"id":"t","kind":"trigger"},{"id":"a","kind":"action"},{"id":"f","kind":"finalize"}],"edges":[{"from":"t","to":"a"},{"from":"a","to":"f"}]}

def test_compiles_bounded_dag():
    c=MissionCompiler().compile(base())
    assert c.is_dag and c.trigger_id=="t" and len(c.nodes)==3 and len(c.compiled_hash)==64

def test_rejects_cycle():
    d=base(); d["edges"] += [{"from":"f","to":"t"}]
    with pytest.raises(MissionCompileError, match="cycle"): MissionCompiler().compile(d)

def test_rejects_unreachable_node():
    d=base(); d["nodes"].append({"id":"x","kind":"action"})
    with pytest.raises(MissionCompileError, match="unreachable"): MissionCompiler().compile(d)

def test_rejects_multiple_triggers():
    d=base(); d["nodes"].append({"id":"t2","kind":"trigger"})
    with pytest.raises(MissionCompileError, match="exactly one trigger"): MissionCompiler().compile(d)

def test_hash_is_deterministic():
    a=MissionCompiler().compile(base())
    d=base(); d["edges"].reverse(); d["nodes"].reverse()
    b=MissionCompiler().compile(d)
    assert a.compiled_hash==b.compiled_hash
