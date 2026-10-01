from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Request, Response, status

from cyclothone.deception.engine import DeceptionEngine

router = APIRouter(prefix="/deception", tags=["deception"])


def _engine() -> DeceptionEngine:
    base = os.getenv("cyclothone_PUBLIC_API_URL") or os.getenv("cyclothone_API_URL")
    if not base:
        raise RuntimeError("cyclothone_PUBLIC_API_URL or cyclothone_API_URL must be configured")
    return DeceptionEngine(callback_base_url=base)


def _request_evidence(request: Request) -> dict[str, Any]:
    forwarded = request.headers.get("x-forwarded-for")
    client_ip = request.client.host if request.client else None
    return {
        "accept": request.headers.get("accept"),
        "content_type": request.headers.get("content-type"),
        "host": request.headers.get("host"),
        "referer": request.headers.get("referer"),
        "forwarded": forwarded,
        "tls": request.url.scheme == "https",
    }


@router.get("/callback/{token}", include_in_schema=False)
@router.post("/callback/{token}", include_in_schema=False)
async def deception_callback(token: str, request: Request) -> Response:
    client_ip = request.client.host if request.client else None
    trigger = await _engine().record_callback(
        token,
        source_ip=client_ip,
        forwarded_for=request.headers.get("x-forwarded-for"),
        user_agent=request.headers.get("user-agent"),
        request_method=request.method,
        request_path=request.url.path,
        source_country=request.headers.get("cf-ipcountry") or request.headers.get("x-country"),
        source_asn=_parse_int(request.headers.get("x-asn")),
        source_org=request.headers.get("x-as-org"),
        evidence=_request_evidence(request),
    )
    # Deliberately return the same response for unknown and known tokens so the
    # endpoint cannot be used to enumerate active deception artifacts.
    if trigger is None:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _parse_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if 0 <= parsed <= 4_294_967_295 else None
