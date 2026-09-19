from cyclothone.gsma.normalize import OperatorResolver

def test_resolve_nigeria():
    ops=[{"id":"mtn-ng","mcc_mnc":"621-30","country":"NG","enabled":True,"number_prefixes":["234803"]}]
    t=OperatorResolver.resolve("+2348031234567",ops)
    assert t and t.operator_id=="mtn-ng"

def test_resolve_requires_verified_prefix():
    ops=[{"id":"mtn-ng","mcc_mnc":"621-30","country":"NG","enabled":True,"number_prefixes":["234803"]}]
    assert OperatorResolver.resolve("+2348012345678",ops) is None

def test_longest_prefix_wins():
    ops=[{"id":"a","mcc_mnc":"621-30","country":"NG","enabled":True,"number_prefixes":["23480"]},{"id":"b","mcc_mnc":"621-31","country":"NG","enabled":True,"number_prefixes":["234803"]}]
    assert OperatorResolver.resolve("+2348031234567",ops).operator_id=="b"
