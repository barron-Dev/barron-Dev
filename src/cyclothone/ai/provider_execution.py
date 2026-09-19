from __future__ import annotations

import asyncio
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from decimal import Decimal
from time import monotonic
from uuid import UUID

from fastapi import HTTPException, status

from cyclothone.response.execution_authority import complete_response_execution
from cyclothone.storage.supabase_client import supabase


@dataclass(frozen=True, slots=True)
class ProviderExecutionResult:
    output_text: str
    tokens_in: int
    tokens_out: int
    tokens_cached: int
    latency_ms: int
    cost_usd: Decimal


def _openai_request(*, model_id: str, input_text: str) -> dict:
    key = os.getenv("OPENAI_API_KEY")
    if not key:
        raise RuntimeError("OPENAI_API_KEY is not configured")
    payload = json.dumps({"model": model_id, "input": input_text}).encode()
    request = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=payload,
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")[:2000]
        raise RuntimeError(f"OpenAI provider error {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError("OpenAI provider transport failure") from exc


def _parse_response(data: dict, *, latency_ms: int) -> ProviderExecutionResult:
    output = data.get("output_text")
    if not isinstance(output, str):
        parts = []
        for item in data.get("output") or []:
            for content in item.get("content") or []:
                if isinstance(content.get("text"), str):
                    parts.append(content["text"])
        output = "".join(parts)
    if not output:
        raise RuntimeError("OpenAI response contained no text output")

    usage = data.get("usage") or {}
    details = usage.get("input_tokens_details") or {}
    return ProviderExecutionResult(
        output_text=output,
        tokens_in=int(usage.get("input_tokens") or 0),
        tokens_out=int(usage.get("output_tokens") or 0),
        tokens_cached=int(details.get("cached_tokens") or 0),
        latency_ms=max(0, latency_ms),
        cost_usd=Decimal("0"),
    )


async def execute_openai_run(
    *, run_id: UUID, provider_id: str, model_id: str, input_text: str,
    actor: str = "ai_provider",
) -> ProviderExecutionResult:
    if provider_id.lower() != "openai":
        raise HTTPException(status_code=409, detail="unsupported provider executor")
    if not input_text:
        raise HTTPException(status_code=400, detail="AI input is required")

    client = await supabase._ensure()
    response = await client.table("ai_runs").select(
        "id,provider_id,model_id,run_state"
    ).eq("id", str(run_id)).limit(1).execute()
    rows = response.data or []
    if not rows:
        raise HTTPException(status_code=404, detail="AI run not found")
    run = rows[0]
    if run["provider_id"] != provider_id or run["model_id"] != model_id:
        raise HTTPException(status_code=409, detail="AI provider identity mismatch")
    if run["run_state"] not in {"AUTHORIZED", "RUNNING"}:
        raise HTTPException(status_code=409, detail="AI run is not executable")

    started = monotonic()
    try:
        data = await asyncio.to_thread(_openai_request, model_id=model_id, input_text=input_text)
        result = _parse_response(data, latency_ms=int((monotonic() - started) * 1000))
        await complete_response_execution(
            run_id=run_id, outcome="COMPLETED",
            actual_cost_usd=result.cost_usd, actor=actor,
        )
        return result
    except Exception as exc:
        try:
            await complete_response_execution(
                run_id=run_id, outcome="FAILED",
                error={"type": type(exc).__name__, "message": str(exc)[:1000]},
                actor=actor,
            )
        except Exception:
            pass
        raise
