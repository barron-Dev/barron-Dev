from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.request import Request, urlopen

from cyclothone.storage.supabase_client import supabase

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SourceDocument:
    source_key: str
    url: str
    body: bytes
    content_type: str | None
    source_version: str | None

    @property
    def manifest_hash(self) -> str:
        return hashlib.sha256(self.body).hexdigest()


def fetch_document(source_key: str, url: str, timeout: int = 20) -> SourceDocument:
    req = Request(url, headers={"User-Agent": "Cyclothone-GIRIL/1.0"})
    with urlopen(req, timeout=timeout) as response:
        body = response.read()
        headers = response.headers
        return SourceDocument(
            source_key=source_key,
            url=url,
            body=body,
            content_type=headers.get("Content-Type"),
            source_version=headers.get("ETag") or headers.get("Last-Modified"),
        )


def parse_iana_tlds(document: SourceDocument) -> list[dict[str, Any]]:
    """Parse IANA's ASCII TLD feed without inventing registry ownership data."""
    rows: list[dict[str, Any]] = []
    for raw in document.body.decode("utf-8-sig").splitlines():
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        rows.append({
            "domain_suffix": value.lower().rstrip("."),
            "rule_type": "PUBLIC_SUFFIX",
            "registrable_domain_required": True,
            "source_version": document.source_version,
        })
    return rows


async def _source(source_key: str) -> dict[str, Any]:
    client = await supabase._ensure()
    result = await client.table("giril_ref_sources").select("*").eq("source_key", source_key).limit(1).execute()
    rows = list(result.data or [])
    if not rows:
        raise RuntimeError(f"GIRIL source is not registered: {source_key}")
    return rows[0]


async def _start_run(source: dict[str, Any]) -> str:
    client = await supabase._ensure()
    result = await client.table("giril_ref_sync_runs").insert({"source_id": source["id"], "status": "RUNNING"}).execute()
    rows = list(result.data or [])
    if not rows:
        raise RuntimeError("GIRIL sync run could not be created")
    return rows[0]["id"]


async def _finish_run(run_id: str, status: str, **fields: Any) -> None:
    client = await supabase._ensure()
    payload = {"status": status, "finished_at": datetime.now(timezone.utc).isoformat(), **fields}
    await client.table("giril_ref_sync_runs").update(payload).eq("id", run_id).execute()


async def sync_iana_tlds() -> dict[str, Any]:
    source = await _source("IANA_ROOT_ZONE")
    url = source.get("api_base_url")
    if not url:
        raise RuntimeError("IANA_ROOT_ZONE has no feed URL")
    run_id = await _start_run(source)
    try:
        document = fetch_document("IANA_ROOT_ZONE", url)
        rows = parse_iana_tlds(document)
        client = await supabase._ensure()
        changed = 0
        for row in rows:
            payload = {k: v for k, v in row.items() if k != "source_version"}
            payload["source_id"] = source["id"]
            payload["rule_version"] = document.source_version or document.manifest_hash[:16]
            payload["effective_from"] = datetime.now(timezone.utc).isoformat()
            result = await client.table("giril_ref_domain_rules").upsert(
                payload, on_conflict="domain_suffix,rule_type,rule_version"
            ).execute()
            changed += len(result.data or [])
        await _finish_run(
            run_id,
            "SUCCEEDED",
            source_version=document.source_version,
            records_seen=len(rows),
            records_changed=changed,
            manifest_hash=document.manifest_hash,
        )
        return {"source_key": "IANA_ROOT_ZONE", "records_seen": len(rows), "records_changed": changed, "manifest_hash": document.manifest_hash}
    except Exception as exc:
        logger.exception("GIRIL IANA synchronization failed")
        await _finish_run(run_id, "FAILED", error_summary=str(exc)[:2000])
        raise


def document_json_hash(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
