from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
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
        ComplianceService._validate_period(start, end)


def test_reversed_period_rejected():
    start = datetime(2026, 1, 2, tzinfo=UTC)
    end = start - timedelta(hours=1)
    with pytest.raises(ComplianceError):
        ComplianceService._validate_period(start, end)


@pytest.mark.asyncio
async def test_list_packs_is_tenant_filtered():
    service = ComplianceService()
    tenant = uuid4()
    fake_response = type("Response", (), {"data": [{"tenant_id": str(tenant)}]})()
    fake_builder = MagicMock()
    fake_builder.eq.return_value = fake_builder
    fake_builder.order.return_value = fake_builder
    fake_builder.limit.return_value = fake_builder
    fake_builder.execute = AsyncMock(return_value=fake_response)
    fake_table = MagicMock()
    fake_table.select.return_value = fake_builder
    fake_client = MagicMock()
    fake_client.table.return_value = fake_table

    async def retry(fn, attempts=2):
        return await fn()

    with patch("sentinel.compliance.service.supabase._ensure", new=AsyncMock(return_value=fake_client)):
        with patch("sentinel.compliance.service.supabase._retry", new=retry):
            result = await service.list_packs(tenant, "soc2")
    assert result == [{"tenant_id": str(tenant)}]
    fake_client.table.assert_called_once_with("compliance_evidence_snapshots")
    fake_builder.eq.assert_any_call("tenant_id", str(tenant))
    fake_builder.eq.assert_any_call("framework_id", "soc2")
    fake_builder.limit.assert_called_once_with(100)


@pytest.mark.asyncio
async def test_record_evidence_source_rows_are_bounded():
    service = ComplianceService()
    tenant = uuid4()
    run_id = uuid4()
    control = {"id": "AC-1", "code": "CC1.1"}
    fake_response = type("Response", (), {"count": 7, "data": []})()
    fake_builder = MagicMock()
    fake_builder.eq.return_value = fake_builder
    fake_builder.gte.return_value = fake_builder
    fake_builder.lt.return_value = fake_builder
    fake_builder.limit.return_value = fake_builder
    fake_builder.execute = AsyncMock(return_value=fake_response)
    fake_client = MagicMock()
    fake_client.table.return_value.select.return_value = fake_builder

    async def retry(fn, attempts=2):
        return await fn()

    with patch("sentinel.compliance.service.supabase._ensure", new=AsyncMock(return_value=fake_client)):
        with patch("sentinel.compliance.service.supabase._retry", new=retry):
            with patch.object(service, "_record_collection_result", new=AsyncMock()):
                with patch.object(service, "_insert", new=AsyncMock()):
                    with patch("sentinel.compliance.service.DEFAULT_FRESHNESS", timedelta(hours=1)):
                        result = await service._record_evidence(
                            tenant, "soc2", control, "detections",
                            datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 1, 2, tzinfo=UTC),
                            None, run_id,
                        )
    assert result == 1
    fake_builder.limit.assert_called_once_with(1)
