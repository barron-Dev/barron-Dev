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

def test_condition_requires_unique_branch_labels():
    d={"mission_id":"m2","version":1,"nodes":[{"id":"t","kind":"trigger"},{"id":"c","kind":"condition"},{"id":"a","kind":"action"},{"id":"b","kind":"action"}],"edges":[{"from":"t","to":"c"},{"from":"c","to":"a","when":"yes"},{"from":"c","to":"b","when":"yes"}]}
    with pytest.raises(MissionCompileError, match="unique labels"): MissionCompiler().compile(d)

def test_parallel_is_bounded():
    d={"mission_id":"m3","version":1,"nodes":[{"id":"t","kind":"trigger"},{"id":"p","kind":"parallel","max_parallel":2},{"id":"a","kind":"action"},{"id":"b","kind":"action"},{"id":"f","kind":"finalize"}],"edges":[{"from":"t","to":"p"},{"from":"p","to":"a"},{"from":"p","to":"b"},{"from":"a","to":"f"},{"from":"b","to":"f"}]}
    assert MissionCompiler().compile(d).max_parallel == 2

def test_parallel_rejects_unbounded_limit():
    d={"mission_id":"m4","version":1,"nodes":[{"id":"t","kind":"trigger"},{"id":"p","kind":"parallel","max_parallel":33},{"id":"a","kind":"action"},{"id":"b","kind":"action"}],"edges":[{"from":"t","to":"p"},{"from":"p","to":"a"},{"from":"p","to":"b"}]}
    with pytest.raises(MissionCompileError, match="max_parallel"): MissionCompiler().compile(d)
