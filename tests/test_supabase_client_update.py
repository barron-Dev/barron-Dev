import pytest

from cyclothone.storage.supabase_client import SupabaseServiceClient


class _Response:
    def __init__(self, data):
        self.data = data


class _UpdateBuilder:
    def __init__(self, response):
        self.response = response
        self.values = None
        self.filters = None
        self.columns = None

    def update(self, values):
        self.values = values
        return self

    def match(self, filters):
        self.filters = filters
        return self

    def select(self, columns):
        self.columns = columns
        return self

    async def execute(self):
        return self.response


class _Table:
    def __init__(self, builder):
        self.builder = builder

    def update(self, values):
        return self.builder.update(values)


class _Client:
    def __init__(self, response):
        self.builder = _UpdateBuilder(response)

    def table(self, table):
        assert table == "dw_alerts"
        return _Table(self.builder)


@pytest.mark.asyncio
async def test_update_uses_supported_async_postgrest_builder_and_returns_first_row():
    expected = {"id": "alert-1", "case_id": "case-1"}
    client = SupabaseServiceClient()
    fake = _Client(_Response([expected, {"id": "alert-2"}]))
    client._client = fake

    result = await client.update(
        "dw_alerts",
        {"case_id": "case-1"},
        id="alert-1",
        tenant_id="tenant-1",
    )

    assert result == expected
    assert fake.builder.values == {"case_id": "case-1"}
    assert fake.builder.filters == {"id": "alert-1", "tenant_id": "tenant-1"}
    assert fake.builder.columns == "*"


@pytest.mark.asyncio
async def test_update_returns_none_when_no_row_matches():
    client = SupabaseServiceClient()
    client._client = _Client(_Response([]))

    result = await client.update(
        "dw_alerts",
        {"case_id": "case-1"},
        id="missing-alert",
        tenant_id="tenant-1",
    )

    assert result is None
