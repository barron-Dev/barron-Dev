import pytest
from fastapi import HTTPException
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from cyclothone.hunting.executor import QueryExecutor
from cyclothone.hunting.parser import Predicate


@pytest.mark.asyncio
async def test_unknown_table_rejected():
    with pytest.raises(HTTPException):
        await QueryExecutor().run(uuid4(), "secrets where x == 1")


@pytest.mark.asyncio
async def test_unknown_field_rejected_before_database_call():
    with patch("cyclothone.hunting.executor.supabase._retry", new_callable=AsyncMock) as retry:
        with pytest.raises(HTTPException):
            await QueryExecutor().run(uuid4(), 'detections where drop_table == 1')
        retry.assert_not_awaited()


@pytest.mark.asyncio
async def test_valid_query_returns_rows():
    fake = AsyncMock()
    fake.data = [{"id": "d1", "verdict": "block"}]
    with patch("cyclothone.hunting.executor.supabase._retry", new_callable=AsyncMock, return_value=fake):
        rows, elapsed = await QueryExecutor().run(uuid4(), 'detections where verdict == "block"')
    assert rows[0]["verdict"] == "block"
    assert elapsed >= 0


def test_or_clause_quotes_and_escapes_reserved_characters():
    clause = QueryExecutor()._to_or_clause(
        Predicate("verdict", "==", 'x,y)\\"z'),
        "detections",
    )
    assert clause.startswith('verdict.eq."')
    assert clause.endswith('"')
    assert "x,y)" in clause
    assert '\\\"' in clause
