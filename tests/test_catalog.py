import pytest
from uuid import uuid4
from unittest.mock import AsyncMock, patch
from cyclothone.api.routes.catalog import get_prefs

@pytest.mark.asyncio
async def test_prefs_fallback():
    principal=AsyncMock(tenant_id=uuid4(),user_id=uuid4())
    fake=AsyncMock(data=[])
    with patch("cyclothone.api.routes.catalog.supabase._retry",return_value=fake):
        out=await get_prefs(principal)
    assert out["default_locale"]=="en"
    assert out["default_region"]=="US"
