from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import os
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID

from cyclothone.federation.anon import FederationAnonymizer
from cyclothone.federation.stix import bundle_from_indicators, parse_stix_bundle
from cyclothone.storage.supabase_client import supabase

_MAX_PAYLOAD = 5_000_000
_TIMEOUT = 15
_AUTH_REF = re.compile(r"^env:[A-Z][A-Z0-9_]{0,127}$")

@dataclass(frozen=True, slots=True)
class ExchangeResult:
    peer_id: UUID
    direction: str
    received: int = 0
    accepted: int = 0
    sent: int = 0
    status: str = "success"
    error: str | None = None
    payload_sha256: str | None = None

def _public_host(host: str) -> None:
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
    except OSError as exc:
        raise ValueError("peer endpoint DNS resolution failed") from exc
    if not addresses:
        raise ValueError("peer endpoint has no resolved address")
    for value in addresses:
        if not ipaddress.ip_address(value).is_global:
            raise ValueError("peer endpoint must resolve to a public address")

def _validated_redirect(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https" or parsed.username or parsed.password or not parsed.hostname:
        raise ValueError("peer endpoint redirected to an invalid URL")
    if parsed.port not in (None, 443):
        raise ValueError("peer endpoint redirect must use port 443")
    _public_host(parsed.hostname)
    return url

class _SafeRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validated_redirect(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def _endpoint(peer: dict[str, object]) -> str:
    raw = str(peer.get("taxii_url") or "").strip()
    if not raw.lower().startswith("https://"):
        raise ValueError("peer has no valid HTTPS TAXII endpoint")
    parsed = urlsplit(raw)
    if parsed.username or parsed.password or not parsed.hostname:
        raise ValueError("TAXII endpoint cannot contain URL credentials")
    if parsed.port not in (None, 443):
        raise ValueError("TAXII endpoint must use port 443")
    _public_host(parsed.hostname)
    base = urlunsplit(("https", parsed.netloc, parsed.path.rstrip("/"), "", ""))
    collection = str(peer.get("taxii_collection") or "").strip()
    if collection and "/collections/" not in base.rstrip("/"):
        base = f"{base}/collections/{collection}"
    if "/objects" not in base.rstrip("/"):
        base = f"{base.rstrip('/')}/objects/"
    return base

def _bearer(peer: dict[str, object]) -> str | None:
    ref = str(peer.get("auth_ref") or "").strip()
    if not ref:
        return None
    if not _AUTH_REF.fullmatch(ref):
        raise ValueError("auth_ref must be an env reference")
    value = os.getenv(ref[4:])
    if not value:
        raise ValueError("configured federation credential is unavailable")
    if len(value) > 8192:
        raise ValueError("configured federation credential is too large")
    return value

def _request(url: str, *, method: str, token: str | None, payload: bytes | None = None) -> bytes:
    headers = {"Accept": "application/taxii+json;version=2.1, application/stix+json;version=2.1", "User-Agent": "Cyclothone-Federation/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if payload is not None:
        headers["Content-Type"] = "application/stix+json;version=2.1"
    request = Request(url, data=payload, headers=headers, method=method)
    try:
        with build_opener(_SafeRedirectHandler()).open(request, timeout=_TIMEOUT) as response:
            _validated_redirect(response.geturl())
            body = response.read(_MAX_PAYLOAD + 1)
            if len(body) > _MAX_PAYLOAD:
                raise ValueError("peer response exceeds federation payload limit")
            return body
    except HTTPError as exc:
        raise RuntimeError(f"peer returned HTTP {exc.code}") from exc
    except URLError as exc:
        raise RuntimeError("peer network request failed") from exc

def _share_value(anon: FederationAnonymizer, ioc_type: str, value: str) -> str:
    if ioc_type == "email": return anon.email(value)
    if ioc_type in {"ipv4", "ipv6"}: return anon.ip(value)
    if ioc_type == "url": return anon.url(value)
    if ioc_type == "domain":
        domain = value.strip().lower().rstrip(".")
        if domain.endswith((".local", ".internal", ".localhost")): return anon.token(domain, context="internal-domain")
        return anon.domain(domain)
    return value

def _sanitize_inbound(anon: FederationAnonymizer, ioc_type: str, value: str) -> str:
    return _share_value(anon, ioc_type, value)

class FederationExchange:
    async def sync_peer(self, *, peer_id: UUID) -> ExchangeResult:
        peer = await supabase.select_one("federation_peers", "id,kind,status,taxii_url,taxii_collection,auth_ref,require_anonymization,share_categories,receive_categories", id=str(peer_id))
        if not peer: raise ValueError("peer not found")
        if peer.get("status") != "active": raise ValueError("peer is not active")
        endpoint, token = _endpoint(peer), _bearer(peer)
        payload = await asyncio.to_thread(_request, endpoint, method="GET", token=token)
        parsed = parse_stix_bundle(payload)[:5000]
        receive_categories = {str(x) for x in (peer.get("receive_categories") or []) if str(x)}
        if receive_categories: parsed = [x for x in parsed if str(x.get("category") or "") in receive_categories]
        anon, accepted, rejected = FederationAnonymizer(), 0, 0
        for indicator in parsed:
            try:
                value_ref = indicator.get("value_ref")
                if not isinstance(value_ref, str) or not value_ref: raise ValueError("foreign indicator has no value")
                sanitized = _sanitize_inbound(anon, str(indicator["ioc_type"]), value_ref)
                await supabase.rpc("upsert_fed_indicator", {"p_peer": str(peer_id), "p_tenant": None, "p_ioc_type": indicator["ioc_type"], "p_value_hash": indicator["value_hash"], "p_value_ref": sanitized, "p_category": indicator.get("category"), "p_severity": "medium", "p_confidence": float(indicator.get("confidence", 0.5))})
                accepted += 1
            except (ValueError, TypeError, KeyError): rejected += 1
        digest = hashlib.sha256(payload).hexdigest()
        status_value = "success" if rejected == 0 else ("partial" if accepted else "failed")
        await supabase.insert_one("fed_shares", {"peer_id": str(peer_id), "direction": "inbound", "ioc_count": accepted, "categories": sorted({str(x.get("category")) for x in parsed if x.get("category")}), "anonymized": True, "status": status_value, "error": None if rejected == 0 else f"{rejected} indicators rejected", "payload_sha256": digest})
        await supabase.update("federation_peers", {"last_receive_at": datetime.now(timezone.utc).isoformat()}, id=str(peer_id))
        return ExchangeResult(peer_id=peer_id, direction="inbound", received=len(parsed), accepted=accepted, status=status_value, error=None if rejected == 0 else f"{rejected} indicators rejected", payload_sha256=digest)

    async def share_peer(self, *, peer_id: UUID, tenant_id: UUID, limit: int = 500) -> ExchangeResult:
        peer = await supabase.select_one("federation_peers", "id,tenant_id,kind,status,taxii_url,taxii_collection,auth_ref,require_anonymization,share_categories,receive_categories", id=str(peer_id))
        if not peer: raise ValueError("peer not found")
        if peer.get("status") != "active": raise ValueError("peer is not active")
        if peer.get("kind") == "tenant" and str(peer.get("tenant_id")) != str(tenant_id): raise ValueError("peer is outside tenant boundary")
        endpoint, token = _endpoint(peer), _bearer(peer)
        categories = [str(x) for x in (peer.get("share_categories") or [])][:100]
        async def _load():
            q = (await supabase._ensure()).table("fed_indicators").select("ioc_type,value_hash,value_ref,category,confidence,created_at,last_seen").eq("source_tenant", str(tenant_id)).eq("whitelisted", False).order("last_seen", desc=True).limit(max(1, min(limit, 5000)))
            if categories: q = q.in_("category", categories)
            return await q.execute()
        rows = list((await supabase._retry(_load, attempts=2)).data or [])
        anon, export_rows = FederationAnonymizer(), []
        for row in rows:
            value = row.get("value_ref")
            if not isinstance(value, str) or not value: continue
            try:
                if bool(peer.get("require_anonymization", True)) or str(row["ioc_type"]) in {"email", "ipv4", "ipv6", "url", "domain"}: value = _share_value(anon, str(row["ioc_type"]), value)
                export_rows.append({**row, "value_ref": value})
            except ValueError: continue
        if not export_rows: return ExchangeResult(peer_id=peer_id, direction="outbound", sent=0, status="success")
        payload, digest = bundle_from_indicators(export_rows), None
        digest = hashlib.sha256(payload).hexdigest()
        try: await asyncio.to_thread(_request, endpoint, method="POST", token=token, payload=payload)
        except Exception as exc:
            await supabase.insert_one("fed_shares", {"peer_id": str(peer_id), "direction": "outbound", "ioc_count": len(export_rows), "categories": categories, "anonymized": True, "status": "failed", "error": str(exc)[:500], "payload_sha256": digest})
            raise
        await supabase.insert_one("fed_shares", {"peer_id": str(peer_id), "direction": "outbound", "ioc_count": len(export_rows), "categories": categories, "anonymized": True, "status": "success", "payload_sha256": digest})
        await supabase.update("federation_peers", {"last_share_at": datetime.now(timezone.utc).isoformat()}, id=str(peer_id))
        return ExchangeResult(peer_id=peer_id, direction="outbound", sent=len(export_rows), payload_sha256=digest)
