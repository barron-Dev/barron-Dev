from __future__ import annotations

import asyncio
import logging
from uuid import UUID

from sentinel.federation.exchange import FederationExchange
from sentinel.storage.supabase_client import supabase

logger = logging.getLogger(__name__)


class FederationScheduler:
    """Bounded federation poll/share loop using the existing API process lifecycle."""

    INTERVAL_SECONDS = 1800
    START_DELAY_SECONDS = 180
    MAX_PEERS_PER_TICK = 100
    MAX_TENANTS_PER_TICK = 500
    MAX_SHARES_PER_TICK = 2000
    MAX_CONCURRENCY = 8

    def __init__(self) -> None:
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._exchange = FederationExchange()
        self._semaphore = asyncio.Semaphore(self.MAX_CONCURRENCY)

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._loop(), name="sentinel-federation")

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _peers(self) -> list[dict]:
        async def _load():
            return await (await supabase._ensure()).table("federation_peers").select(
                "id,kind,status,taxii_url,taxii_collection,auth_ref,trust_level,reputation,"
                "require_anonymization,share_categories,receive_categories"
            ).eq("status", "active").order("created_at").limit(self.MAX_PEERS_PER_TICK).execute()

        try:
            response = await supabase._retry(_load, attempts=2)
            return list(response.data or [])
        except Exception:
            logger.exception("federation peer discovery failed")
            return []

    async def _tenant_ids(self) -> list[str]:
        """Discover only tenants that currently own federated indicators."""
        async def _load():
            return await (await supabase._ensure()).table("fed_indicators").select(
                "source_tenant"
            ).not_.is_("source_tenant", "null").limit(self.MAX_TENANTS_PER_TICK).execute()

        try:
            response = await supabase._retry(_load, attempts=2)
            return sorted({str(row["source_tenant"]) for row in (response.data or []) if row.get("source_tenant")})
        except Exception:
            logger.exception("federation tenant discovery failed")
            return []

    async def _sync(self, peer: dict) -> None:
        async with self._semaphore:
            try:
                await self._exchange.sync_peer(peer_id=peer["id"])
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("federation inbound sync failed peer=%s", peer.get("id"))

    async def _share(self, peer: dict, tenant_id: str) -> None:
        async with self._semaphore:
            try:
                await self._exchange.share_peer(peer_id=peer["id"], tenant_id=UUID(tenant_id))
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("federation outbound share failed peer=%s tenant=%s", peer.get("id"), tenant_id)

    async def _loop(self) -> None:
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=self.START_DELAY_SECONDS)
        except asyncio.TimeoutError:
            pass

        while not self._stop.is_set():
            try:
                peers = await self._peers()
                tenants = await self._tenant_ids()
                sync_tasks = [asyncio.create_task(self._sync(peer)) for peer in peers if peer.get("taxii_url")]
                if sync_tasks:
                    await asyncio.gather(*sync_tasks)

                remaining = self.MAX_SHARES_PER_TICK
                share_tasks: list[asyncio.Task[None]] = []
                for peer in peers:
                    if remaining <= 0 or self._stop.is_set():
                        break
                    if int(peer.get("trust_level") or 0) < 1:
                        continue
                    for tenant_id in tenants:
                        if remaining <= 0 or self._stop.is_set():
                            break
                        share_tasks.append(asyncio.create_task(self._share(peer, tenant_id)))
                        remaining -= 1
                if share_tasks:
                    await asyncio.gather(*share_tasks)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("federation scheduler tick failed")

            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.INTERVAL_SECONDS)
            except asyncio.TimeoutError:
                pass
