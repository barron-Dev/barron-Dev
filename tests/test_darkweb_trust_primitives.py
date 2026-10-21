import unittest
from cyclothone.darkweb.trust_primitives import (
 anomaly_score, cosine_distance, isolation_username, minhash_signature,
 minhash_similarity, mirror_verdict, normalize_text, sha256_hex, simhash64,
 validate_v3_hostname,
)
class TrustPrimitivesTests(unittest.TestCase):
 def test_v3_syntax_is_not_trust(self):
  self.assertTrue(validate_v3_hostname("a"*56+".onion"))
  self.assertFalse(validate_v3_hostname("a"*55+".onion"))
  self.assertFalse(validate_v3_hostname("a"*56+".onion.evil"))
 def test_isolation_username_is_opaque_and_scoped(self):
  key=b"k"*32; a=isolation_username("tenant-a","source-1",key)
  self.assertEqual(a,isolation_username("tenant-a","source-1",key))
  self.assertNotEqual(a,isolation_username("tenant-b","source-1",key))
  self.assertNotEqual(a,isolation_username("tenant-a","source-2",key))
  self.assertNotIn("tenant-a",a)
  with self.assertRaises(ValueError): isolation_username("t","s",b"short")
 def test_normalization_and_hashes(self):
  self.assertEqual(normalize_text(" HELLO\n World "), "hello world")
  self.assertEqual(sha256_hex(b"abc"),"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
  text="one two three four five six seven eight nine"
  self.assertEqual(minhash_similarity(minhash_signature(text),minhash_signature(text)),1.0)
  self.assertEqual(len(simhash64(text)),16)
 def test_mirror_verdict_requires_signature_pin_and_host(self):
  host="b"*56+".onion"
  self.assertEqual(mirror_verdict(signature_valid=True,signer_fingerprint="AA BB",pinned_fingerprint="aabb",signed_hosts=[host],current_hostname=host).status,"verified")
  self.assertEqual(mirror_verdict(signature_valid=True,signer_fingerprint="AA",pinned_fingerprint="BB",signed_hosts=[host],current_hostname=host).status,"fingerprint_mismatch")
  self.assertEqual(mirror_verdict(signature_valid=False,signer_fingerprint="AA",pinned_fingerprint="AA",signed_hosts=[host],current_hostname=host).status,"invalid_signature")
  self.assertEqual(mirror_verdict(signature_valid=True,signer_fingerprint="AA",pinned_fingerprint="AA",signed_hosts=[],current_hostname=host).status,"host_not_in_signed_list")
  self.assertEqual(mirror_verdict(signature_valid=True,signer_fingerprint="AA",pinned_fingerprint=None,signed_hosts=[host],current_hostname=host).status,"unsigned")
 def test_similarity_and_anomaly_are_bounded(self):
  self.assertEqual(cosine_distance([1,0],[1,0]),0.0)
  self.assertEqual(cosine_distance([1,0],[0,1]),1.0)
  self.assertEqual(anomaly_score(0.5,threshold=1.0,recency_weight=0.5),0.25)
  with self.assertRaises(ValueError): cosine_distance([0,0],[1,1])
if __name__=="__main__": unittest.main()
