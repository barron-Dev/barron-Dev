from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from contextlib import asynccontextmanager
from typing import AsyncIterator
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

BLOCKED_NETS = tuple(ipaddress.ip_network(x) for x in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10",
    "2001:db8::/32",
))


class EgressDenied(Exception):
    pass


def _is_private(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return any(ip in net for net in BLOCKED_NETS) or ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast


async def _resolve(host: str) -> list[tuple]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, lambda: socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    )


async def assert_host_allowed(host: str) -> None:
    if not host or host.lower() == "localhost" or host.endswith(".localhost"):
        raise EgressDenied("local host is forbidden")
    try:
        infos = await _resolve(host)
    except socket.gaierror:
        return
    for _, _, _, _, sockaddr in infos:
        if _is_private(sockaddr[0]):
            raise EgressDenied(f"host {host} resolves to blocked address")


@asynccontextmanager
async def guard_route(route) -> AsyncIterator[bool]:
    try:
        url = route.request.url
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"}:
            await route.abort("blockedbyclient")
            yield False
            return
        await assert_host_allowed(parts.hostname or "")
        yield True
    except EgressDenied as exc:
        logger.info("egress denied: %s", exc)
        try:
            await route.abort("blockedbyclient")
        except Exception:
            pass
        yield False
    except Exception as exc:
        logger.warning("egress guard failed closed: %s", exc)
        try:
            await route.abort("failed")
        except Exception:
            pass
        yield False
