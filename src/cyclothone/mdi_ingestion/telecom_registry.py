"""Strict CSV parser for a reviewed, licensed MCC/MNC source export."""
from __future__ import annotations
import csv, hashlib, io, re
from typing import Any
MCC=re.compile(r"^[0-9]{3}$"); MNC=re.compile(r"^[0-9]{2,3}$"); ISO=re.compile(r"^[A-Z]{2}$")
class TelecomRegistryError(ValueError): pass

def parse_registry_csv(content: bytes) -> tuple[list[dict[str,Any]],str]:
    if not content or len(content)>10*1024*1024: raise TelecomRegistryError("CSV must be non-empty and <=10 MiB")
    digest=hashlib.sha256(content).hexdigest()
    try: reader=csv.DictReader(io.StringIO(content.decode("utf-8-sig")))
    except UnicodeDecodeError as exc: raise TelecomRegistryError("CSV must be UTF-8") from exc
    required={"mcc","mnc","country_iso","provider_name"}
    if not reader.fieldnames or not required.issubset(set(reader.fieldnames)): raise TelecomRegistryError("missing required headers")
    result=[]; seen=set()
    for line,row in enumerate(reader,start=2):
        mcc,mnc=(row.get("mcc") or "").strip(),(row.get("mnc") or "").strip()
        country,provider=(row.get("country_iso") or "").strip().upper(),(row.get("provider_name") or "").strip()
        if not MCC.fullmatch(mcc) or not MNC.fullmatch(mnc) or not ISO.fullmatch(country) or not provider:
            raise TelecomRegistryError(f"invalid row at CSV line {line}")
        if (mcc,mnc) in seen: raise TelecomRegistryError(f"duplicate MCC/MNC at CSV line {line}")
        seen.add((mcc,mnc)); result.append({"mcc":mcc,"mnc":mnc,"country_iso":country,"provider_name":provider,"source_sha256":digest})
    if not result: raise TelecomRegistryError("registry contains no rows")
    return result,digest

def persist_registry_rows(rows: list[dict[str, Any]], *, source_name: str, source_url: str | None = None) -> int:
    """Upsert validated rows into the global reference table from a trusted worker."""
    import os
    from urllib.parse import urlparse
    import httpx
    if not source_name.strip() or len(source_name)>200:
        raise TelecomRegistryError("source_name is required and must be <=200 characters")
    if source_url is not None:
        parsed=urlparse(source_url)
        if parsed.scheme!="https" or not parsed.netloc:
            raise TelecomRegistryError("source_url must be HTTPS")
    if os.environ.get("CYCLOTHONE_MDI_INGESTION_ENABLED","").lower()!="true":
        raise TelecomRegistryError("MDI ingestion is disabled")
    base=os.environ.get("SUPABASE_URL","").rstrip("/")
    key=os.environ.get("SUPABASE_SERVICE_ROLE_KEY","")
    if not base.startswith("https://") or not key:
        raise TelecomRegistryError("trusted worker Supabase configuration missing")
    if not rows:
        return 0
    payload=[]
    for row in rows:
        payload.append({"mcc":row["mcc"],"mnc":row["mnc"],"country_iso":row["country_iso"],
          "provider_name":row["provider_name"],"source_sha256":row["source_sha256"],
          "source_name":source_name,"source_url":source_url,"imported_at":__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()})
    with httpx.Client(timeout=httpx.Timeout(10,connect=3),follow_redirects=False) as client:
        response=client.post(f"{base}/rest/v1/mdi_global_telecom_registry?on_conflict=mcc,mnc",
          headers={"apikey":key,"Authorization":f"Bearer {key}","Content-Type":"application/json",
                   "Prefer":"resolution=merge-duplicates,return=minimal"},json=payload)
    if response.status_code not in (200,201,204):
        raise TelecomRegistryError(f"registry upsert failed ({response.status_code}); response omitted")
    return len(payload)
