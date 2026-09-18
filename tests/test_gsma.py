from cyclothone.gsma.normalize import OperatorResolver

def test_resolve_nigeria():
    ops=[{"id":"mtn-ng","mcc_mnc":"621-30","country":"NG"}]
    t=OperatorResolver.resolve("+2348012345678",ops)
    assert t and t.operator_id=="mtn-ng"

def test_resolve_unknown_country():
    assert OperatorResolver.resolve("+9999999",[]) is None
