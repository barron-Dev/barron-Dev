from cyclothone.banking.fapi.policy import FapiPolicy,FapiRequest,validate_https_uri

def client(**kw):
    x={"client_id":"bank-app","status":"active","redirect_uris":["https://bank.example/cb"],"scopes":["openid","payments"],"require_pkce":True,"require_dpop":True}
    x.update(kw); return x

def test_valid_fapi_policy():
    v=FapiPolicy(client()).validate(FapiRequest("bank-app","https://bank.example/cb","code","S256challenge","S256","openid payments","jti-12345678901234",1000,"https://api.example/token","POST"),now=1000)
    assert v.allowed

def test_pkce_required():
    v=FapiPolicy(client(require_dpop=False)).validate(FapiRequest("bank-app","https://bank.example/cb","code",scope="openid"),now=1000)
    assert not v.allowed
    assert any(r["code"]=="pkce_s256_required" for r in v.reasons)

def test_redirect_must_match():
    v=FapiPolicy(client(require_dpop=False)).validate(FapiRequest("bank-app","https://evil.example/cb","code","x","S256","openid"),now=1000)
    assert not v.allowed

def test_dpop_replay_window():
    v=FapiPolicy(client()).validate(FapiRequest("bank-app","https://bank.example/cb","code","x","S256","openid","jti-12345678901234",1000,"https://api.example/token","POST"),now=1301)
    assert not v.allowed

def test_https_redirect():
    assert validate_https_uri("https://bank.example/cb")
    assert not validate_https_uri("http://bank.example/cb")
