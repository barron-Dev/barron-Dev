from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest

from sentinel.compliance.catalog import CONTROLS, FRAMEWORKS
from sentinel.compliance.evaluator import ComplianceEvaluator
from sentinel.compliance.service import ComplianceError, ComplianceService


def test_catalog_contains_seven_frameworks_and_27_controls():
    assert set(FRAMEWORKS) == {"soc2", "iso27001", "gdpr", "hipaa", "pci_dss", "uae_pdpl", "ndpa_ng"}
    assert len(CONTROLS) == 28


def test_invalid_period_rejected():
    with pytest.raises(ComplianceError):
        ComplianceService._validate_period(datetime.now(UTC), datetime.now(UTC) - timedelta(minutes=1))

@pytest.mark.asyncio
async def test_evaluator_fails_closed_for_missing_collector():
    evaluator = ComplianceEvaluator()
    with patch.object(evaluator, "_sync_catalog", new=AsyncMock()), patch.object(evaluator, "_control_row", new=AsyncMock(return_value=None)):
        with patch("sentinel.compliance.evaluator.CONTROLS", [{"id":"x.manual","framework":"soc2","code":"X","title":"Manual","category":"governance","evidence_sources":[],"check_key":"missing"}]):
            result = await evaluator.evaluate(uuid4(), "soc2", datetime.now(UTC) - timedelta(days=1), datetime.now(UTC))
    assert result["unknown"] == 1
    assert result["controls"][0]["status"] == "unknown"

@pytest.mark.asyncio
async def test_endpoint_check_is_truthful_when_source_unavailable():
    from sentinel.compliance.checks import check_endpoint_coverage
    with patch("sentinel.compliance.checks.supabase._retry", new=AsyncMock(side_effect=RuntimeError("offline"))):
        status, score, evidence = await check_endpoint_coverage(uuid4(), datetime.now(UTC) - timedelta(days=1), datetime.now(UTC))
    assert status == "unknown"
    assert score == 0.0
    assert evidence["availability"] == "unavailable"
