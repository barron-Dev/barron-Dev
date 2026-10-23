import unittest
from cyclothone.darkweb.evidence_integrity import canonical_json_sha256, entity_match_score, merkle_root, normalize_anchor, sha256_hex
class EvidenceIntegrityTests(unittest.TestCase):
 def test_canonical_hash_stable(self):
  self.assertEqual(canonical_json_sha256({"b":2,"a":1}),canonical_json_sha256({"a":1,"b":2}))
 def test_merkle_root_deterministic_and_order_sensitive(self):
  a=sha256_hex(b"a"); b=sha256_hex(b"b"); c=sha256_hex(b"c")
  self.assertEqual(merkle_root([a,b]),merkle_root([a,b]))
  self.assertNotEqual(merkle_root([a,b]),merkle_root([b,a]))
  self.assertNotEqual(merkle_root([a,b,c]),merkle_root([a,b]))
  with self.assertRaises(ValueError): merkle_root([])
 def test_entity_matches_are_candidates_not_merges(self):
  self.assertEqual(entity_match_score(1.0,2,True).disposition,"auto_candidate")
  self.assertEqual(entity_match_score(0.95,2,False).disposition,"human_review")
  self.assertEqual(entity_match_score(0.2,0,True).disposition,"no_link")
 def test_anchor_normalization_is_conservative(self):
  self.assertEqual(normalize_anchor("eth_address","0x"+"A"*40),"0x"+"a"*40)
  self.assertEqual(normalize_anchor("email","User@EXAMPLE.COM"),"user@example.com")
  with self.assertRaises(ValueError): normalize_anchor("btc_address","not-validated")
if __name__=="__main__": unittest.main()
