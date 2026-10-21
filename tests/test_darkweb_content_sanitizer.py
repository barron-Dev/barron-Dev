import unittest
from cyclothone.darkweb.content_sanitizer import sanitize_html
class SanitizerTests(unittest.TestCase):
 def test_removes_active_content_and_event_attributes(self):
  raw=b'<h1 onclick="alert(1)">Hi</h1><script>exfiltrate()</script><img src="https://x.invalid/pixel"><p style="background:url(https://x.invalid)">safe</p>'
  out=sanitize_html(raw)
  self.assertNotIn("onclick",out["safe_html"]); self.assertNotIn("exfiltrate",out["safe_html"])
  self.assertNotIn("<img",out["safe_html"]); self.assertNotIn("url(",out["safe_html"])
  self.assertIn("Hi",out["text"]); self.assertIn("safe",out["text"])
 def test_rejects_javascript_links_and_keeps_safe_https_link(self):
  out=sanitize_html(b'<a href="javascript:alert(1)" onclick="x()">bad</a><a href="https://example.invalid/a">good</a>')
  self.assertNotIn("javascript:",out["safe_html"]); self.assertNotIn("onclick",out["safe_html"])
  self.assertIn('href="https://example.invalid/a"',out["safe_html"])
 def test_bounds_input(self):
  with self.assertRaises(ValueError): sanitize_html(b"x"*11,max_bytes=10)
if __name__=="__main__": unittest.main()
