from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from supabase import AsyncClient, acreate_client

T = TypeVar("T")


class SupabaseServiceClient:
    """Single privileged server-side Supabase client.

    The secret key is never accepted from request data. Legacy service_role is
    supported only as a migration fallback while Supabase transitions keys.
    """

    def __init__(self) -> None:
        self._client: AsyncClient | None = None
        self._lock = asyncio.Lock()

    async def _ensure(self) -> AsyncClient:
        if self._client is not None:
            return self._client
        async with self._lock:
            if self._client is None:
                url = os.getenv("SUPABASE_URL")
                key = os.getenv("SUPABASE_SECRET_KEY") or os.getenv("SUPABASE_SERVICE_ROLE_KEY")
                if not url or not key:
                    raise RuntimeError("SUPABASE_URL and SUPABASE_SECRET_KEY are required")
                self._client = await acreate_client(url, key)
        return self._client

    async def _retry(
        self,
        operation: Callable[[], Awaitable[T]],
        *,
        attempts: int = 3,
    ) -> T:
        if attempts < 1:
            raise ValueError("attempts must be >= 1")
        last_error: Exception | None = None
        for attempt in range(attempts):
            try:
                return await operation()
            except Exception as error:
                last_error = error
                if attempt + 1 < attempts:
                    await asyncio.sleep(0.2 * (2**attempt))
        assert last_error is not None
        raise last_error

    async def select_one(self, table: str, columns: str, **filters: Any) -> dict[str, Any] | None:
        async def operation() -> dict[str, Any] | None:
            client = await self._ensure()
            query = client.table(table).select(columns)
            for column, value in filters.items():
                query = query.eq(column, value)
            response = await query.limit(1).execute()
            rows = response.data or []
            return rows[0] if rows else None

        return await self._retry(operation)


supabase = SupabaseServiceClient()
