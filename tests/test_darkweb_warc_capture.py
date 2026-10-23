import gzip, tempfile, unittest
from datetime import datetime, timezone
from pathlib import Path
from cyclothone.darkweb.warc_capture import write_warc_capture
class WarcCaptureTests(unittest.TestCase):
 def test_writes_warc_records_and_hashes(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"capture.warc.gz"
   result=write_warc_capture(p,url="https://example.invalid/",request_message=b"GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n",response_message=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",content_bytes=b"hi",captured_at=datetime.now(timezone.utc))
   raw=p.read_bytes()
   self.assertEqual(result["content_sha256"],"8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4")
   self.assertEqual(result["record_count"],3)
   self.assertEqual(len(result["warc_record_ids"]),3)
   self.assertIn(b"WARC/1.1",gzip.decompress(raw))
 def test_exclusive_create_prevents_retry_overwrite(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"x.warc.gz"; args=dict(url="https://example.invalid/",request_message=b"req",response_message=b"resp",content_bytes=b"resp",captured_at=datetime.now(timezone.utc))
   write_warc_capture(p,**args)
   with self.assertRaises(FileExistsError): write_warc_capture(p,**args)
if __name__=="__main__": unittest.main()
