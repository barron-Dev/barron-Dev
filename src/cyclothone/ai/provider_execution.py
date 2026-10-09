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

from fastapi import HTTPException

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


def _parse_response(
    data: dict,
    *,
    latency_ms: int,
    cost_meta: dict,
) -> ProviderExecutionResult:
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

    usage = data.get("usage")
    if not isinstance(usage, dict) or "input_tokens" not in usage or "output_tokens" not in usage:
        raise RuntimeError("OpenAI response omitted token usage; refusing to record zero cost")
    tokens_in = int(usage["input_tokens"])
    tokens_out = int(usage["output_tokens"])
    details = usage.get("input_tokens_details") or {}
    tokens_cached = int(details.get("cached_tokens") or 0)
    if min(tokens_in, tokens_out, tokens_cached) < 0 or tokens_cached > tokens_in:
        raise RuntimeError("OpenAI response contained invalid token usage")

    required_prices = (
        "input_usd_per_million_tokens",
        "cached_input_usd_per_million_tokens",
        "output_usd_per_million_tokens",
    )
    if not isinstance(cost_meta, dict) or any(key not in cost_meta for key in required_prices):
        raise RuntimeError("Model pricing is not registered; refusing to record zero cost")

    input_rate = Decimal(str(cost_meta["input_usd_per_million_tokens"]))
    cached_rate = Decimal(str(cost_meta["cached_input_usd_per_million_tokens"]))
    output_rate = Decimal(str(cost_meta["output_usd_per_million_tokens"]))
    if min(input_rate, cached_rate, output_rate) < 0:
        raise RuntimeError("Model pricing contains a negative rate")

    uncached_tokens = tokens_in - tokens_cached
    cost = (
        Decimal(uncached_tokens) * input_rate
        + Decimal(tokens_cached) * cached_rate
        + Decimal(tokens_out) * output_rate
    ) / Decimal(1_000_000)

    return ProviderExecutionResult(
        output_text=output,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        tokens_cached=tokens_cached,
        latency_ms=max(0, latency_ms),
        cost_usd=cost.quantize(Decimal("0.00000001")),
    )


async def execute_openai_run(
    *, run_id: UUID, input_text: str, actor: str = "ai_provider",
) -> ProviderExecutionResult:
    if not input_text:
        raise HTTPException(status_code=400, detail="AI input is required")

    client = await supabase._ensure()
    response = await client.table("ai_runs").select(
        "id,tenant_id,provider_id,model_id,run_state"
    ).eq("id", str(run_id)).limit(1).execute()
    rows = response.data or []
    if not rows:
        raise HTTPException(status_code=404, detail="AI run not found")
    run = rows[0]
    tenant_id = str(run["tenant_id"])
    provider_id = str(run["provider_id"])
    model_id = str(run["model_id"])
    if provider_id.lower() != "openai":
        raise HTTPException(status_code=409, detail="unsupported provider executor")
    if run["run_state"] not in {"AUTHORIZED", "RUNNING"}:
        raise HTTPException(status_code=409, detail="AI run is not executable")

    provider_response = await client.table("ai_providers").select(
        "lifecycle_state,circuit_state"
    ).eq("id", provider_id).limit(1).execute()
    providers = provider_response.data or []
    if not providers or providers[0].get("lifecycle_state") != "ACTIVE" or providers[0].get("circuit_state") == "OPEN":
        raise HTTPException(status_code=409, detail="OpenAI provider is not active in the registry")

    model_response = await client.table("ai_models").select(
        "provider_model_key,lifecycle_state,cost_meta"
    ).eq("id", model_id).eq("tenant_id", tenant_id).limit(1).execute()
    models = model_response.data or []
    if not models or models[0].get("lifecycle_state") != "ACTIVE":
        raise HTTPException(status_code=409, detail="AI model is not active for this tenant")
    model = models[0]
    provider_model_key = str(model.get("provider_model_key") or "")
    cost_meta = model.get("cost_meta") or {}
    if not provider_model_key:
        raise HTTPException(status_code=409, detail="AI model has no provider model key")

    claim_response = await client.rpc(
        "ai_claim_provider_execution",
        {"p_run_id": str(run_id), "p_actor": actor},
    ).execute()
    claim = claim_response.data or {}
    if isinstance(claim, list):
        claim = claim[0] if claim else {}
    if claim.get("claimed") is not True:
        raise HTTPException(
            status_code=409,
            detail=f"AI run execution already claimed or finalized ({claim.get('reason', 'unknown')})",
        )

    started = monotonic()
    try:
        data = await asyncio.to_thread(_openai_request, model_id=provider_model_key, input_text=input_text)
        result = _parse_response(
            data,
            latency_ms=int((monotonic() - started) * 1000),
            cost_meta=cost_meta,
        )
        await client.rpc(
            "ai_record_provider_usage",
            {
                "p_run_id": str(run_id),
                "p_tokens_in": result.tokens_in,
                "p_tokens_out": result.tokens_out,
                "p_tokens_cached": result.tokens_cached,
                "p_latency_ms": result.latency_ms,
                "p_cost_usd": str(result.cost_usd),
            },
        ).execute()
        await complete_response_execution(
            run_id=run_id, outcome="COMPLETED",
            actual_cost_usd=result.cost_usd, actor=actor,
        )
        return result
    except Exception:
        # Once the canonical claim succeeds, provider execution may have incurred
        # billable usage even if the transport, parsing, settlement, or completion
        # step fails. Never finalize as FAILED with the shared zero-cost default:
        # that can erase cost evidence and make reconciliation impossible.
        # STUCK is non-terminal and the claim RPC will not re-issue the provider call
        # while the run remains outside AUTHORIZED.
        try:
            await client.rpc(
                "ai_transition_run",
                {
                    "p_run_id": str(run_id),
                    "p_to": "STUCK",
                    "p_reason": "provider_execution_outcome_requires_reconciliation",
                    "p_actor": actor,
                },
            ).execute()
        except Exception:
            # Preserve the original execution/settlement exception. If the database
            # is unavailable, the run may remain RUNNING; claim remains fail-closed.
            pass
        raise
