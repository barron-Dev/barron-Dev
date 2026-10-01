from cyclothone.zk.commitment import HashCommitment
from cyclothone.zk.merkle import MerkleTree

def test_commitment_roundtrip_and_tamper():
 c=HashCommitment.commit("detections",1200)
 assert HashCommitment.verify(c.metric,c.bucket,c.blinding_b64,c.commitment_hex)
 assert not HashCommitment.verify(c.metric,1300,c.blinding_b64,c.commitment_hex)

def test_bucket_rejects_invalid():
 try: HashCommitment.bucket_value(-1)
 except ValueError: pass
 else: assert False

def test_merkle_proof_and_tamper():
 leaves=[HashCommitment.commit("a",100).commitment_hex,HashCommitment.commit("b",200).commitment_hex,HashCommitment.commit("c",300).commitment_hex]
 t=MerkleTree(leaves); p=t.proof(2)
 assert MerkleTree.verify(p.leaf,p.index,p.path,t.root)
 assert not MerkleTree.verify(leaves[1],p.index,p.path,t.root)

def test_merkle_rejects_bad_hex():
 try: MerkleTree(["zz"])
 except ValueError: pass
 else: assert False
