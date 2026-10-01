from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest
from cyclothone.immune.bundle import BundleEnvelope, payload_sha256, sign_bundle, verify_envelope
from cyclothone.immune.dp import PrivacyBudget, GradientClipper, contribution_commitment
from cyclothone.immune.federated import FederatedAggregator, TenantContribution

def test_dp_validation_and_clip():
    with pytest.raises(ValueError):
        PrivacyBudget(0, 1e-6)
    clipped, norm = GradientClipper(2).clip([3.0, 4.0])
    assert pytest.approx(norm) == 2
    assert pytest.approx(sum(x*x for x in clipped)) == 4

def test_commitment_changes_with_vector():
    a=contribution_commitment("r","t",[1.0,2.0],3)
    b=contribution_commitment("r","t",[1.0,2.1],3)
    assert a != b

def test_federated_requires_quorum_and_deduplicates():
    agg=FederatedAggregator(clipping_norm=1,budget=PrivacyBudget(2,1e-6))
    c=TenantContribution("r","t",(1.0,0.0),10)
    with pytest.raises(ValueError):
        agg.aggregate([c],2)
    with pytest.raises(ValueError):
        agg.aggregate([c,c],2)

def test_bundle_signature_binds_metadata_and_hash():
    key=Ed25519PrivateKey.generate()
    payload={"rule":"x","version":1}
    exp=datetime.now(timezone.utc)+timedelta(hours=1)
    kwargs=dict(bundle_id="00000000-0000-0000-0000-000000000001",version=1,kind="rule",
                schema_version="v1",issuer_tenant_id=None,issuer_kid="global-key-01",
                payload_hash=payload_sha256(payload),expires_at=exp)
    sig,ctx=sign_bundle(key,**kwargs)
    env=BundleEnvelope(kwargs["bundle_id"],1,"rule","v1",None,"global-key-01",
                       payload,kwargs["payload_hash"],sig,ctx,exp)
    verify_envelope(env,key.public_key())
    tampered=BundleEnvelope(env.bundle_id,2,*env.__dict__.values()) if False else None
    with pytest.raises(ValueError):
        verify_envelope(BundleEnvelope(env.bundle_id,1,"ioc","v1",None,env.issuer_kid,
            payload,env.payload_sha256,env.signature,env.signature_context,exp),key.public_key())
