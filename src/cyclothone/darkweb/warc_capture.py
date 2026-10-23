"""Minimal deterministic WARC/1.1 capture writer for already-captured raw HTTP messages.

This module does not fetch URLs. The caller must supply exact request/response message
bytes from an approved capture adapter and must not pass decompressed response bodies
as though they were wire-exact.
"""
from __future__ import annotations
import base64, gzip, hashlib, os, re, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _digest(data: bytes) -> str:
    return "sha256:" + base64.b32encode(hashlib.sha256(data).digest()).decode("ascii").rstrip("=").lower()

def _record(record_type: str, target_uri: str, payload: bytes, when: datetime,
            content_type: str, extra_headers: Iterable[tuple[str,str]] = ()) -> bytes:
    if when.tzinfo is None:
        raise ValueError("capture timestamp must be timezone-aware")
    date=when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    headers=[
      ("WARC-Type",record_type),("WARC-Record-ID",f"<urn:uuid:{uuid.uuid4()}>"),
      ("WARC-Date",date),("WARC-Target-URI",target_uri),
      ("WARC-Content-Type",content_type),("WARC-Content-Length",str(len(payload))),
      ("WARC-Block-Digest",_digest(payload)),
    ]
    headers.extend(extra_headers)
    raw=("WARC/1.1\r\n"+"".join(f"{k}: {v}\r\n" for k,v in headers)+"\r\n").encode("ascii")+payload+b"\r\n\r\n"
    return gzip.compress(raw,mtime=0)

def write_warc_capture(path: str | os.PathLike[str], *, url: str, request_message: bytes,
                       response_message: bytes, content_bytes: bytes,
                       captured_at: datetime, warcinfo: dict[str,str] | None = None) -> dict[str, object]:
    """Write one gzip-member WARC file with warcinfo, request and response records."""
    if not url.startswith(("http://","https://")):
        raise ValueError("WARC target must be an explicit HTTP(S) URI")
    if not request_message or not response_message:
        raise ValueError("raw request and response messages are required")
    if captured_at.tzinfo is None:
        raise ValueError("captured_at must be timezone-aware")
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    info={"software":"Cyclothone DW evidence capture","format":"WARC File Format 1.1"}
    info.update(warcinfo or {})
    info_bytes=("".join(f"{k}: {v}\r\n" for k,v in sorted(info.items()))).encode("utf-8")
    records=[
      _record("warcinfo",url,info_bytes,captured_at,"application/warc-fields"),
      _record("request",url,request_message,captured_at,"application/http; msgtype=request"),
      _record("response",url,response_message,captured_at,"application/http; msgtype=response"),
    ]
    # Use exclusive creation so retries cannot silently overwrite an existing archive.
    with path.open("xb") as fh:
        for record in records: fh.write(record)
        fh.flush(); os.fsync(fh.fileno())
    archive_bytes=path.read_bytes()
    return {
      "warc_path":str(path),
      "warc_sha256":sha256_hex(archive_bytes),
      "content_sha256":sha256_hex(content_bytes),
      "content_length":len(content_bytes),
      "warc_record_ids":_record_ids(archive_bytes),
      "record_count":3,
      "captured_at":captured_at.astimezone(timezone.utc).isoformat(),
    }

def _record_ids(compressed: bytes) -> list[str]:
    # gzip members are concatenated; parse only WARC headers from each member.
    ids=[]
    offset=0
    while offset<len(compressed):
        dec=zlib_decompress_member(compressed[offset:])
        marker=b"\r\n\r\n"
        header_end=dec.find(marker)
        if header_end<0: raise ValueError("malformed WARC record header")
        header=dec[:header_end].decode("ascii","strict")
        for line in header.split("\r\n"):
            if line.lower().startswith("warc-record-id:"): ids.append(line.split(":",1)[1].strip().strip("<>"))
        consumed=_gzip_member_size(compressed[offset:])
        if consumed<=0: raise ValueError("invalid gzip member")
        offset+=consumed
    return ids

def zlib_decompress_member(data: bytes) -> bytes:
    import zlib
    obj=zlib.decompressobj(16+zlib.MAX_WBITS)
    return obj.decompress(data)+obj.flush()

def _gzip_member_size(data: bytes) -> int:
    import zlib
    obj=zlib.decompressobj(16+zlib.MAX_WBITS)
    obj.decompress(data)
    return len(data)-len(obj.unused_data)
