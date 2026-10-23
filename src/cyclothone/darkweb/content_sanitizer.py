"""Fail-closed HTML-to-safe-subset sanitizer; never fetches URLs or executes scripts."""
from __future__ import annotations
import hashlib
from html import escape
from html.parser import HTMLParser
from urllib.parse import urlsplit

ALLOWED_TAGS={"p","a","ul","ol","li","blockquote","h1","h2","h3","h4","table","thead","tbody","tr","th","td","pre","code","em","strong","br"}
DROP_CONTENT={"script","style","noscript","iframe","object","embed","svg","math","template","canvas","video","audio"}
VOID_TAGS={"br"}
class _Sanitizer(HTMLParser):
 def __init__(self):
  super().__init__(convert_charrefs=True); self.out=[]; self.stack=[]; self.drop_depth=0; self.drop_tag=None; self.text=[]
 def handle_starttag(self,tag,attrs):
  tag=tag.lower()
  if self.drop_depth:
   if tag==self.drop_tag: self.drop_depth+=1
   return
  if tag in DROP_CONTENT:
   self.drop_tag=tag; self.drop_depth=1; return
  if tag not in ALLOWED_TAGS: return
  safe_attrs=""
  if tag=="a":
   href=dict(attrs).get("href","")
   parsed=urlsplit(href)
   if parsed.scheme in ("http","https") and parsed.hostname and not parsed.username and not parsed.password:
    safe_attrs=' href="'+escape(href,quote=True)+'" rel="nofollow noreferrer noopener"'
  self.out.append("<"+tag+safe_attrs+">")
  if tag not in VOID_TAGS: self.stack.append(tag)
 def handle_startendtag(self,tag,attrs): self.handle_starttag(tag,attrs); self.handle_endtag(tag)
 def handle_endtag(self,tag):
  tag=tag.lower()
  if self.drop_depth:
   if tag==self.drop_tag:
    self.drop_depth-=1
    if not self.drop_depth: self.drop_tag=None
   return
  if tag not in ALLOWED_TAGS or tag in VOID_TAGS or tag not in self.stack: return
  while self.stack:
   current=self.stack.pop(); self.out.append("</"+current+">")
   if current==tag: break
 def handle_data(self,data):
  if not self.drop_depth:
   safe=escape(data,quote=False); self.out.append(safe); self.text.append(data)
 def finish(self):
  while self.stack: self.out.append("</"+self.stack.pop()+">")
  return "".join(self.out)

def sanitize_html(raw: bytes, *, max_bytes: int=2_000_000) -> dict[str,str|int]:
 """Sanitize bounded HTML bytes; output is safe-subset HTML, not a trusted web page."""
 if len(raw)>max_bytes: raise ValueError("content exceeds sanitizer byte limit")
 decoded=raw.decode("utf-8",errors="replace")
 parser=_Sanitizer()
 parser.feed(decoded); parser.close()
 safe_html=parser.finish()
 text=" ".join(" ".join(parser.text).split())
 text_hash=hashlib.sha256(text.encode("utf-8")).hexdigest()
 return {"text":text,"safe_html":safe_html,"text_sha256":text_hash,"input_bytes":len(raw),"sanitizer_version":"cyclothone-stdlib-1"}
