from __future__ import annotations

from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest

from cyclothone.api.routes.device_enrollment_tokens import (
    CreateEnrollmentTokenRequest,
    create_enrollment_token,
)
from cyclothone.developer.auth import DeveloperPrincipal


@pytest.mark.asyncio
async def test_enrollment_token_is_hashed_and_never_sent_to_rpc():
    principal = DeveloperPrincipal(
        tenant_id=str(uuid4()),
        app_id=str(uuid4()),
        scopes=frozenset({"console:write"}),
        user_id=None,
        auth_type="api_key",
    )
    rpc = AsyncMock(
        return_value=[{
            "token_id": str(uuid4()),
            "tenant_id": principal.tenant_id,
            "expires_at": "2026-09-18T18:00:00+00:00",
        }]
    )

    with (
        patch(
            "cyclothone.api.routes.device_enrollment_tokens.secrets.token_urlsafe",
            return_value="test-secret-token",
        ),
        patch(
            "cyclothone.api.routes.device_enrollment_tokens.supabase.rpc",
            new=rpc,
        ),
    ):
        result = await create_enrollment_token(
            CreateEnrollmentTokenRequest(expires_in_seconds=3600),
            principal,
        )

    assert result["token"] == "test-secret-token"
    payload = rpc.await_args.args[1]
    assert payload["p_token_hash"] != "test-secret-token"
    assert len(payload["p_token_hash"]) == 64
    assert payload["p_app_id"] == principal.app_id
