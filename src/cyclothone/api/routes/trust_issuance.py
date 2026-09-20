from __future__ import annotations

from fastapi import APIRouter, Depends

from cyclothone.developer.auth import DeveloperPrincipal, authenticate_request
from cyclothone.storage.supabase_client import supabase

router = APIRouter(prefix="/trust", tags=["trust-infrastructure"])


def _read(principal: DeveloperPrincipal = Depends(authenticate_request)) -> DeveloperPrincipal:
    principal.require(("console:read",))
    return principal


@router.get("/certificates/issuance-preflight")
async def certificate_issuance_preflight(_: DeveloperPrincipal = Depends(_read)):
    checks = {
        "authority_key": False,
        "certificate_signing_path": False,
        "policy_engine": False,
    }
    authority = {"status": "UNKNOWN", "active_key_count": 0}
    errors: list[str] = []

    try:
        keys = await supabase.select(
            "trust_public_key_directory",
            "key_id,status,valid_from,valid_until",
            purpose="TRUST_CERTIFICATE",
            status="ACTIVE",
        )
        authority["active_key_count"] = len(keys)
        authority["status"] = "AVAILABLE" if keys else "NOT_CONFIGURED"
        checks["authority_key"] = bool(keys)

        functions = await supabase.rpc("trust_re_evaluation_queue_stats", {})
        checks["certificate_signing_path"] = functions is not None

        policies = await supabase.select(
            "trust_policies",
            "id,status",
            status="ACTIVE",
        )
        checks["policy_engine"] = policies is not None
    except Exception:
        errors.append("preflight_dependency_unavailable")

    issuance_ready = all(checks.values())

    return {
        "status": "READY" if issuance_ready else "NOT_READY",
        "capability": "CERTIFICATE_ISSUANCE",
        "issuance_ready": issuance_ready,
        "checks": checks,
        "authority": authority,
        "blocking_reasons": (
            [key for key, value in checks.items() if not value]
            + errors
        ),
    }
