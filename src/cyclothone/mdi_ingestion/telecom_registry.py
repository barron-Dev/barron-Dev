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
