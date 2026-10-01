from __future__ import annotations

from collections.abc import Callable, Iterable

from fastapi import Depends, Header, HTTPException

from cyclothone.security.jwt import Principal, authenticate_user


async def get_principal(authorization: str | None = Header(None)) -> Principal:
    return await authenticate_user(authorization)


def require_role(*roles: str) -> Callable:
    allowed = frozenset(roles)

    async def dependency(principal: Principal = Depends(get_principal)) -> Principal:
        if allowed and principal.role not in allowed:
            raise HTTPException(403, "insufficient role")
        return principal

    return dependency
