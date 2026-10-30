import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cyclothone.global_integrity.crypto import GlobalIntegrityError,canonical_json,context_hash,device_fingerprint,principal_fingerprint,verify_ed25519

def test_canonical_json_is_order_independent():
    assert canonical_json({"b":2,"a":1}) == canonical_json({"a":1,"b":2})

def test_fingerprints_are_tenant_scoped():
    assert device_fingerprint("tenant-a","install") != device_fingerprint("tenant-b","install")
    assert principal_fingerprint("tenant-a","developer","app-1") != principal_fingerprint("tenant-b","developer","app-1")

def test_ed25519_signature_binds_exact_payload():
    private=Ed25519PrivateKey.generate()
    public=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    payload={"challenge_id":"abc","action":"download","hash":"a"*64}
    signature=base64.b64encode(private.sign(canonical_json(payload))).decode()
    assert verify_ed25519(public,signature,payload)
    assert not verify_ed25519(public,signature,{**payload,"action":"payment"})

def test_context_hash_is_deterministic():
    assert context_hash({"project":"alpha","hash":"a"*64}) == context_hash({"hash":"a"*64,"project":"alpha"})

def test_invalid_key_rejected():
    try:
        verify_ed25519("not a key","AA==",{})
        assert False
    except GlobalIntegrityError:
        pass
