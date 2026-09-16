from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest

from sentinel.compliance.service import ComplianceError, ComplianceService


def test_invalid_framework_rejected():
    with pytest.raises(ComplianceError):
        ComplianceService._validate_framework("not_a_framework")


def test_naive_period_rejected():
    start = datetime(2026, 1, 1)
    end = datetime(2026, 1, 2)
    with pytest.raises(ComplianceError):
        ComplianceService._validate("soc2", start, end)


def test_reversed_period_rejected():
    start = datetime(2026, 1, 2, tzinfo=UTC)
    end = start - timedelta(hours=1)
    with pytest.raises(ComplianceError):
        ComplianceService._validate("soc2", start, end)


@pytest.mark.asyncio
async def test_list_packs_is_tenant_filtered():
    service = ComplianceService()
    tenant = uuid4()
    with patch.object(service, "_select", new=AsyncMock(return_value=[{"tenant_id": str(tenant)}])) as select:
        result = await service.list_packs(tenant, "soc2")
    assert result == [{"tenant_id": str(tenant)}]
    select.assert_awaited_once_with(
        "compliance_packs",
        "id,run_id,framework,period_start,period_end,status,object_ref,sha256,generated_at,metadata",
        [("tenant_id", str(tenant)), ("framework", "soc2")],
    )


@pytest.mark.asyncio
async def test_source_rows_are_bounded():
    service = ComplianceService()
    fake_response = type("Response", (), {"data": []})()
    fake_builder = AsyncMock()
    fake_builder.eq.return_value = fake_builder
    fake_builder.gte.return_value = fake_builder
    fake_builder.lt.return_value = fake_builder
    fake_builder.limit.return_value = fake_builder
    fake_builder.execute.return_value = fake_response
    fake_client = AsyncMock()
    fake_client.table.return_value.select.return_value = fake_builder
    with patch.object(service, "_source_rows", wraps=service._source_rows):
        with patch("sentinel.compliance.service.supabase._ensure", new=AsyncMock(return_value=fake_client)):
            with patch("sentinel.compliance.service.supabase._retry", new=AsyncMock(side_effect=lambda fn, attempts=2: fn())):
                rows = await service._source_rows(
                    "detections", "id,created_at,verdict,score,detector", uuid4(),
                    datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 1, 2, tzinfo=UTC),
                )
    assert rows == []
    fake_builder.limit.assert_called_once_with(1000)
